"""Immutable result models shared by the controller, verifier, service and CLI.

Every model serialises to a JSON-compatible ``dict`` via ``to_dict()``. The serialised
field names are part of the CLI's documented output contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    """Current UTC time as an ISO 8601 string with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    """What one verification provider reported."""

    provider: str
    ok: bool
    ip: str | None = None
    is_tor: bool | None = None
    latency_ms: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of one exit verification round.

    ``ip`` is populated **only** when ``ok`` is true, so a consumer that forgets to check
    ``ok`` still cannot act on an unverified address. ``candidate_ip`` carries the
    plurality address (if any) for diagnostics.
    """

    ok: bool
    ip: str | None
    tor_confirmed: bool | None
    quorum: int
    agreeing: int
    dissenting: int = 0
    responded: int = 0
    candidate_ip: str | None = None
    observations: tuple[ProviderObservation, ...] = ()
    checked_at: str = field(default_factory=utc_now_iso)
    duration_ms: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["observations"] = [o.to_dict() for o in self.observations]
        return data

    @classmethod
    def unavailable(cls, error: str) -> VerificationResult:
        """A placeholder for a verification that never ran."""
        return cls(ok=False, ip=None, tor_confirmed=None, quorum=0, agreeing=0, error=error)


@dataclass(frozen=True, slots=True)
class ControlStatus:
    """Tor control-plane state as reported over the control connection."""

    connected: bool
    authenticated: bool
    tor_version: str | None = None
    bootstrap_phase: str | None = None
    bootstrap_progress: int | None = None
    circuit_established: bool | None = None
    network_liveness: str | None = None
    socks_listeners: tuple[str, ...] | None = None
    """Tor's SOCKS listeners, or ``None`` when this Tor version did not report them."""
    circuit_count: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["socks_listeners"] = None if self.socks_listeners is None else list(self.socks_listeners)
        return data


@dataclass(frozen=True, slots=True)
class HealthCheck:
    """One named health assertion."""

    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Aggregate health of the control plane, SOCKS wiring and Tor exit."""

    healthy: bool
    control: ControlStatus
    exit: VerificationResult
    checks: tuple[HealthCheck, ...] = ()
    checked_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checks": [c.to_dict() for c in self.checks],
            "control": self.control.to_dict(),
            "exit": self.exit.to_dict(),
            "checked_at": self.checked_at,
        }


@dataclass(frozen=True, slots=True)
class NewnymOutcome:
    """Result of sending ``SIGNAL NEWNYM``.

    ``accepted`` means Tor answered ``250 OK``. ``applied`` means Tor subsequently emitted
    the ``650 SIGNAL NEWNYM`` event, which it does only when it actually applies the signal.
    """

    accepted: bool
    applied: bool
    confirmation_seconds: float | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class RotationResult:
    """Outcome of one rotation, with every fact recorded separately."""

    request_id: str
    requested_at: str
    completed_at: str
    signal_accepted: bool
    signal_applied: bool
    before: VerificationResult
    after: VerificationResult
    exit_changed: bool | None
    verified: bool
    attempts: int
    error: str | None = None
    signal_confirmation_ms: int | None = None
    duration_ms: int | None = None
    warnings: tuple[str, ...] = ()

    @property
    def successful_change(self) -> bool:
        """True only for an applied, verified rotation onto a *different* verified exit."""
        return self.operation_succeeded and self.exit_changed is True

    @property
    def operation_succeeded(self) -> bool:
        """True when the rotation met the configured success policy."""
        return self.signal_accepted and self.signal_applied and self.verified and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "requested_at": self.requested_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "signal_accepted": self.signal_accepted,
            "signal_applied": self.signal_applied,
            "signal_confirmation_ms": self.signal_confirmation_ms,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "exit_changed": self.exit_changed,
            "verified": self.verified,
            "successful_change": self.successful_change,
            "operation_succeeded": self.operation_succeeded,
            "attempts": self.attempts,
            "error": self.error,
            "warnings": list(self.warnings),
        }
