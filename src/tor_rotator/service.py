"""Rotation orchestration: health checks, the rotation state machine, and the scheduler.

Rotation state machine (see ``docs/ARCHITECTURE.md``)::

    lock -> verify(before) -> NEWNYM -> [confirmed?] -> settle -> verify(after) x N
         -> apply success policy -> persist state/metrics -> unlock

Control-plane facts (accepted, applied) and data-plane facts (verified, exit changed) are
recorded separately. A failure at any step is captured in the result; it is never
reported as success, and it never skips persistence.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

from . import metrics
from ._net import is_loopback_address
from .config import AppConfig, SocksConfig, is_loopback_host
from .control import ControlBackend, TorControlClient
from .errors import ExitCode, LockBusyError, StateError, TorRotatorError
from .lock import ProcessLock
from .models import (
    ControlStatus,
    HealthCheck,
    HealthReport,
    RotationResult,
    VerificationResult,
    utc_now_iso,
)
from .state import StateStore, record_rotation
from .verify import ExitVerifier

LOG = logging.getLogger("tor_rotator")


class Verifier(Protocol):
    """Anything that can verify the current exit (an :class:`ExitVerifier`, or a test double)."""

    def verify(self) -> VerificationResult: ...


class TorRotatorService:
    """High-level operations: :meth:`health`, :meth:`verify`, :meth:`rotate`, :meth:`watch`."""

    def __init__(
        self,
        config: AppConfig,
        verifier: Verifier | None = None,
        control_factory: Callable[[], ControlBackend] | None = None,
        *,
        sleep: Callable[[float], object] | None = None,
        clock: Callable[[], float] = time.monotonic,
        uniform: Callable[[float, float], float] | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.verifier = verifier or ExitVerifier(config.socks, config.verify)
        self._control_factory = control_factory or self._default_control
        self._stop = threading.Event()
        self._sleep: Callable[[float], object] = sleep or self._stop.wait
        self._clock = clock
        self._uniform = uniform or secrets.SystemRandom().uniform
        self.state = StateStore(config.runtime.state_file)

    def _default_control(self) -> ControlBackend:
        return TorControlClient(self.config.control, self.config.control_password())

    # ------------------------------------------------------------ lifecycle

    def request_stop(self) -> None:
        """Ask a running :meth:`watch` loop (and any in-progress waits) to finish."""
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # ------------------------------------------------------------- queries

    def verify(self) -> VerificationResult:
        """Verify the current exit without touching circuits."""
        return self.verifier.verify()

    def health(self) -> HealthReport:
        """Check the control plane, Tor bootstrap/liveness, SOCKS wiring, and the exit."""
        try:
            with self._control_factory() as control:
                control_status = control.status()
        except (TorRotatorError, OSError) as exc:
            control_status = ControlStatus(connected=False, authenticated=False, error=str(exc))
        exit_status = self.verifier.verify()
        checks = _health_checks(control_status, exit_status, self.config.socks)
        return HealthReport(
            healthy=all(check.ok for check in checks),
            control=control_status,
            exit=exit_status,
            checks=checks,
        )

    # ------------------------------------------------------------ rotation

    def rotate(self) -> RotationResult:
        """Request clean circuits and verify the result, under the rotation lock.

        :raises LockBusyError: another rotation is in progress (nothing was changed).
        """
        with ProcessLock(self.config.runtime.lock_file):
            return self._rotate_locked()

    def _rotate_locked(self) -> RotationResult:
        started = self._clock()
        request_id = str(uuid.uuid4())
        requested_at = utc_now_iso()
        LOG.info("rotation started", extra={"request_id": request_id})

        before = self.verifier.verify()
        accepted = applied = False
        confirmation_ms: int | None = None
        after = VerificationResult.unavailable("rotation did not reach post-rotation verification")
        attempts = 0
        error: str | None = None

        try:
            with self._control_factory() as control:
                outcome = control.signal_newnym()
        except (TorRotatorError, OSError) as exc:
            error = f"NEWNYM request failed: {exc}"
        else:
            accepted, applied = outcome.accepted, outcome.applied
            if outcome.confirmation_seconds is not None:
                confirmation_ms = round(outcome.confirmation_seconds * 1000)
            if not applied:
                error = outcome.detail or "Tor did not confirm applying SIGNAL NEWNYM"
            elif self.config.rotation.settle_seconds > 0:
                self._sleep(self.config.rotation.settle_seconds)
            after, attempts = self._verify_after(before, applied=applied)
            error = error or self._policy_error(before, after)

        result = RotationResult(
            request_id=request_id,
            requested_at=requested_at,
            completed_at=utc_now_iso(),
            duration_ms=round((self._clock() - started) * 1000),
            signal_accepted=accepted,
            signal_applied=applied,
            signal_confirmation_ms=confirmation_ms,
            before=before,
            after=after,
            exit_changed=(before.ip != after.ip) if (before.ok and after.ok) else None,
            verified=after.ok,
            attempts=attempts,
            error=error,
        )
        result = self._persist(result)
        self._log_rotation(result)
        return result

    def _verify_after(self, before: VerificationResult, *, applied: bool) -> tuple[VerificationResult, int]:
        verify_cfg = self.config.verify
        max_attempts = verify_cfg.attempts_after_rotation if applied else 1
        want_change = self.config.rotation.require_exit_change and before.ok
        after = VerificationResult.unavailable("post-rotation verification did not run")
        attempts = 0
        for attempt in range(1, max_attempts + 1):
            attempts = attempt
            after = self.verifier.verify()
            if after.ok and (not want_change or after.ip != before.ip):
                break
            if attempt == max_attempts or self.stopping:
                break
            self._sleep(verify_cfg.retry_delay_seconds)
        return after, attempts

    def _policy_error(self, before: VerificationResult, after: VerificationResult) -> str | None:
        if not after.ok:
            return after.error or "post-rotation exit verification failed"
        if self.config.rotation.require_exit_change:
            if not before.ok:
                return (
                    "rotation.require_exit_change is set but the pre-rotation exit was not "
                    "verified, so an exit change cannot be proven"
                )
            if before.ip == after.ip:
                return "NEWNYM was applied but a different exit IP was not verified"
        return None

    def _persist(self, result: RotationResult) -> RotationResult:
        warnings: list[str] = []
        try:
            previous = self.state.read()
        except StateError as exc:
            warnings.append(f"previous state was unreadable and counters were reset: {exc}")
            previous = None
        if warnings:
            result = replace(result, warnings=tuple(warnings))
        snapshot = record_rotation(previous, result)
        try:
            self.state.write(snapshot)
        except OSError as exc:
            warnings.append(f"state was not persisted: {exc}")
        else:
            metrics_file = self.config.runtime.metrics_file
            if metrics_file:
                try:
                    metrics.write(metrics_file, metrics.render(snapshot))
                except OSError as exc:
                    warnings.append(f"metrics were not written: {exc}")
        for warning in warnings:
            LOG.error(warning, extra={"request_id": result.request_id})
        return replace(result, warnings=tuple(warnings)) if warnings else result

    @staticmethod
    def _log_rotation(result: RotationResult) -> None:
        LOG.log(
            logging.INFO if result.operation_succeeded else logging.WARNING,
            "rotation completed" if result.operation_succeeded else "rotation failed",
            extra={
                "request_id": result.request_id,
                "signal_accepted": result.signal_accepted,
                "signal_applied": result.signal_applied,
                "verified": result.verified,
                "exit_changed": result.exit_changed,
                "before_ip": result.before.ip,
                "after_ip": result.after.ip,
                "attempts": result.attempts,
                "duration_ms": result.duration_ms,
                "error": result.error,
            },
        )

    # ----------------------------------------------------------- scheduler

    def watch(self, *, once: bool = False) -> ExitCode:
        """Rotate every ``interval_seconds`` (+ optional jitter) until stopped.

        Individual failures are logged and survived. The loop ends on
        :meth:`request_stop`, or after ``max_consecutive_failures`` failures in a row
        (when that limit is non-zero), so a supervisor such as systemd can react.
        """
        rotation = self.config.rotation
        LOG.info(
            "watch started",
            extra={"interval_seconds": rotation.interval_seconds, "jitter_seconds": rotation.jitter_seconds},
        )
        consecutive_failures = 0
        while not self.stopping:
            cycle_started = self._clock()
            outcome = self._watch_iteration()
            if once:
                return outcome
            if outcome is ExitCode.OK:
                consecutive_failures = 0
            elif outcome is ExitCode.FAILED:
                consecutive_failures += 1
                limit = rotation.max_consecutive_failures
                if limit and consecutive_failures >= limit:
                    LOG.critical(
                        "stopping after consecutive rotation failures",
                        extra={"consecutive_failures": consecutive_failures},
                    )
                    return ExitCode.FAILED
            jitter = self._uniform(0.0, rotation.jitter_seconds) if rotation.jitter_seconds else 0.0
            elapsed = self._clock() - cycle_started
            if not self.stopping:
                self._sleep(max(0.0, rotation.interval_seconds + jitter - elapsed))
        LOG.info("watch stopped")
        return ExitCode.OK

    def _watch_iteration(self) -> ExitCode:
        try:
            result = self.rotate()
        except LockBusyError as exc:
            LOG.warning("rotation skipped", extra={"reason": str(exc)})
            return ExitCode.BUSY
        except (TorRotatorError, OSError) as exc:
            LOG.error("rotation could not run", extra={"error": str(exc)})  # noqa: TRY400
            return ExitCode.FAILED
        except Exception:  # a long-running daemon must survive unexpected errors
            LOG.exception("unexpected error during rotation")
            return ExitCode.FAILED
        return ExitCode.OK if result.operation_succeeded else ExitCode.FAILED


def _listener_matches(listener: str, socks: SocksConfig) -> bool:
    if socks.mode == "unix":
        if not listener.startswith("unix:"):
            return False
        path = listener.removeprefix("unix:")
        return path == socks.socket_path or os.path.realpath(path) == os.path.realpath(socks.socket_path)
    host, sep, port = listener.rpartition(":")
    if not sep or not port.isdigit() or int(port) != socks.port:
        return False
    host = host.strip("[]")
    return host == socks.host or (is_loopback_address(host) and is_loopback_host(socks.host))


def _health_checks(
    control: ControlStatus, exit_status: VerificationResult, socks: SocksConfig
) -> tuple[HealthCheck, ...]:
    checks = [
        HealthCheck(
            "control",
            control.connected and control.authenticated,
            f"Tor {control.tor_version}" if control.connected else (control.error or "unavailable"),
        )
    ]
    if control.connected:
        progress = control.bootstrap_progress
        checks.append(
            HealthCheck(
                "bootstrap",
                progress == 100,
                f"{progress}%" if progress is not None else "bootstrap progress not reported",
            )
        )
        if control.circuit_established is not None:
            checks.append(
                HealthCheck(
                    "circuit_established",
                    control.circuit_established,
                    "Tor reports a usable circuit"
                    if control.circuit_established
                    else "Tor has not established a circuit",
                )
            )
        if control.network_liveness is not None:
            checks.append(
                HealthCheck(
                    "network_liveness",
                    control.network_liveness == "up",
                    f"Tor reports the network {control.network_liveness}",
                )
            )
        if control.socks_listeners is not None:
            configured = f"unix:{socks.socket_path}" if socks.mode == "unix" else f"{socks.host}:{socks.port}"
            matched = any(_listener_matches(item, socks) for item in control.socks_listeners)
            listing = ", ".join(control.socks_listeners) or "none"
            checks.append(
                HealthCheck(
                    "socks_listener",
                    matched,
                    f"configured {configured} is a Tor SOCKS listener"
                    if matched
                    else f"configured {configured} is not a Tor SOCKS listener (Tor: {listing})",
                )
            )
    checks.append(
        HealthCheck(
            "exit",
            exit_status.ok,
            f"verified Tor exit {exit_status.ip}" if exit_status.ok else (exit_status.error or "failed"),
        )
    )
    return tuple(checks)
