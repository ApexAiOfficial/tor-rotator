from __future__ import annotations

import json
import os

import pytest

from conftest import offline_config, runtime_for
from fakes import EXIT_A, EXIT_B, FakeTorControl
from tor_rotator.config import RotationConfig, SocksConfig, VerifyConfig
from tor_rotator.errors import ControlError, ExitCode, LockBusyError
from tor_rotator.lock import ProcessLock
from tor_rotator.models import ControlStatus, NewnymOutcome, VerificationResult
from tor_rotator.service import TorRotatorService, _listener_matches


class FakeControl:
    def __init__(self, outcome=None, fail=None, status=None):
        self.outcome = outcome or NewnymOutcome(accepted=True, applied=True, confirmation_seconds=0.01)
        self.fail = fail
        self._status = status or ControlStatus(
            True,
            True,
            tor_version="0.4.8.16",
            bootstrap_progress=100,
            circuit_established=True,
            network_liveness="up",
            socks_listeners=("127.0.0.1:9050",),
        )
        self.signals = 0

    def __enter__(self):
        if self.fail:
            raise self.fail
        return self

    def __exit__(self, *exc):
        return None

    def status(self):
        return self._status

    def signal_newnym(self):
        self.signals += 1
        return self.outcome


class Sequence:
    def __init__(self, *values):
        self.values = list(values)
        self.calls = 0

    def verify(self):
        self.calls += 1
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


def vr(ip=EXIT_A, ok=True):
    return VerificationResult(
        ok=ok,
        ip=ip if ok else None,
        candidate_ip=ip,
        tor_confirmed=True if ok else None,
        quorum=2,
        agreeing=2 if ok else 0,
        error=None if ok else "verification failed",
    )


def service(tmp_path, verifier, control=None, sleeps=None, **sections):
    control = control or FakeControl()
    return TorRotatorService(
        offline_config(tmp_path, **sections),
        verifier=verifier,
        control_factory=lambda: control,
        sleep=(sleeps.append if sleeps is not None else (lambda _s: None)),
    )


def require_change(**kw):
    return RotationConfig(interval_seconds=10, settle_seconds=0, require_exit_change=True, **kw)


# --- rotation ------------------------------------------------------------------------


def test_verified_change(tmp_path):
    svc = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B)))
    result = svc.rotate()
    assert result.operation_succeeded and result.successful_change
    assert result.exit_changed is True
    assert result.signal_confirmation_ms == 10
    assert result.attempts == 1
    state = svc.state.read()
    assert state["counters"] == {
        "rotations_total": 1,
        "rotations_succeeded": 1,
        "rotations_failed": 0,
        "exit_changes_total": 1,
    }
    assert state["consecutive_failures"] == 0
    assert state["last_success_at"] == result.completed_at


def test_same_exit_is_valid_when_change_not_required(tmp_path):
    result = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_A))).rotate()
    assert result.operation_succeeded
    assert result.exit_changed is False
    assert not result.successful_change


def test_same_exit_fails_policy_when_change_required(tmp_path):
    sleeps: list[float] = []
    verifier = Sequence(vr(EXIT_A), vr(EXIT_A))
    result = service(tmp_path, verifier, sleeps=sleeps, rotation=require_change()).rotate()
    assert not result.operation_succeeded
    assert "different exit IP was not verified" in (result.error or "")
    assert result.attempts == 2
    assert verifier.calls == 3
    assert sleeps == [0]


def test_change_required_retries_until_new_exit(tmp_path):
    result = service(
        tmp_path, Sequence(vr(EXIT_A), vr(EXIT_A), vr(EXIT_B)), rotation=require_change()
    ).rotate()
    assert result.operation_succeeded
    assert result.attempts == 2


def test_regression_change_required_but_before_unverified_is_not_success(tmp_path):
    # 1.0.1 compared None == "ip" -> False and reported success without a proven change.
    result = service(tmp_path, Sequence(vr(EXIT_A, ok=False), vr(EXIT_B)), rotation=require_change()).rotate()
    assert not result.operation_succeeded
    assert result.exit_changed is None
    assert "cannot be proven" in (result.error or "")
    assert result.attempts == 1


def test_regression_exit_changed_only_compares_verified_addresses(tmp_path):
    # 1.0.1 compared raw IPs even when one side had failed verification.
    result = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B, ok=False))).rotate()
    assert result.exit_changed is None
    assert result.after.ip is None
    assert not result.operation_succeeded


def test_settle_and_retry_delays(tmp_path):
    sleeps: list[float] = []
    svc = service(
        tmp_path,
        Sequence(vr(EXIT_A), vr(ok=False), vr(EXIT_B)),
        sleeps=sleeps,
        verify=VerifyConfig(attempts_after_rotation=3, retry_delay_seconds=2.5),
        rotation=RotationConfig(interval_seconds=10, settle_seconds=1.5),
    )
    result = svc.rotate()
    assert result.operation_succeeded
    assert sleeps == [1.5, 2.5]


def test_control_failure_never_reports_success(tmp_path):
    control = FakeControl(fail=ControlError("cannot connect to Tor ControlPort"))
    result = service(tmp_path, Sequence(vr()), control=control).rotate()
    assert not result.signal_accepted and not result.signal_applied
    assert not result.verified
    assert result.attempts == 0
    assert "NEWNYM request failed" in (result.error or "")
    assert svc_state(tmp_path)["counters"]["rotations_failed"] == 1


def svc_state(tmp_path):
    return json.loads((tmp_path / "state.json").read_text())


def test_unapplied_newnym_is_a_failure_with_single_verification(tmp_path):
    control = FakeControl(outcome=NewnymOutcome(accepted=True, applied=False, detail="deferred"))
    verifier = Sequence(vr(EXIT_A), vr(EXIT_A))
    result = service(tmp_path, verifier, control=control).rotate()
    assert result.signal_accepted and not result.signal_applied
    assert result.error == "deferred"
    assert result.attempts == 1
    assert result.verified  # the exit is still healthy; the rotation itself failed


def test_unapplied_newnym_without_detail(tmp_path):
    control = FakeControl(outcome=NewnymOutcome(accepted=True, applied=False))
    result = service(tmp_path, Sequence(vr()), control=control).rotate()
    assert "did not confirm" in (result.error or "")


def test_stop_request_cuts_retries_short(tmp_path):
    svc = service(tmp_path, Sequence(vr(EXIT_A), vr(ok=False)))
    svc.request_stop()
    result = svc.rotate()
    assert result.attempts == 1
    assert svc.stopping


def test_failure_streak_and_last_success_tracking(tmp_path):
    good = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B))).rotate()
    service(tmp_path, Sequence(vr(EXIT_A), vr(ok=False))).rotate()
    service(tmp_path, Sequence(vr(EXIT_A), vr(ok=False))).rotate()
    state = svc_state(tmp_path)
    assert state["consecutive_failures"] == 2
    assert state["last_success_at"] == good.completed_at
    assert state["counters"]["rotations_total"] == 3


def test_corrupt_previous_state_is_reported_and_reset(tmp_path):
    (tmp_path / "state.json").write_text("{not json")
    result = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B))).rotate()
    assert result.operation_succeeded
    assert any("unreadable" in w for w in result.warnings)
    assert svc_state(tmp_path)["counters"]["rotations_total"] == 1
    assert svc_state(tmp_path)["last_rotation"]["warnings"]


def test_state_write_failure_is_a_warning(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    runtime = runtime_for(tmp_path, state_file=str(blocker / "state.json"))
    result = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B)), runtime=runtime).rotate()
    assert result.operation_succeeded
    assert any("not persisted" in w for w in result.warnings)


def test_metrics_file_is_written(tmp_path):
    runtime = runtime_for(tmp_path, metrics_file=str(tmp_path / "metrics" / "tor_rotator.prom"))
    service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B)), runtime=runtime).rotate()
    text = (tmp_path / "metrics" / "tor_rotator.prom").read_text()
    assert 'tor_rotator_rotations_total{outcome="succeeded"} 1' in text
    assert EXIT_A not in text
    assert oct((tmp_path / "metrics" / "tor_rotator.prom").stat().st_mode & 0o777) == "0o644"


def test_metrics_write_failure_is_a_warning(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    runtime = runtime_for(tmp_path, metrics_file=str(blocker / "m.prom"))
    result = service(tmp_path, Sequence(vr(EXIT_A), vr(EXIT_B)), runtime=runtime).rotate()
    assert any("metrics were not written" in w for w in result.warnings)


def test_concurrent_rotation_is_rejected(tmp_path):
    svc = service(tmp_path, Sequence(vr()))
    with ProcessLock(tmp_path / "rotate.lock"), pytest.raises(LockBusyError):
        svc.rotate()


def test_service_validates_config(tmp_path):
    from tor_rotator.errors import ConfigurationError

    bad = offline_config(tmp_path, verify=VerifyConfig(quorum=9))
    with pytest.raises(ConfigurationError):
        TorRotatorService(bad, verifier=Sequence(vr()))


def test_default_control_factory_resolves_password_lazily(tmp_path, monkeypatch):
    from tor_rotator.config import ControlConfig
    from tor_rotator.control import TorControlClient

    monkeypatch.setenv("TR_TEST_PW", "pw")
    config = offline_config(tmp_path, control=ControlConfig(password_env="TR_TEST_PW"))
    svc = TorRotatorService(config, verifier=Sequence(vr()))
    control = svc._control_factory()
    assert isinstance(control, TorControlClient)
    assert control._password == "pw"


def test_full_stack_rotation(stack):
    svc = TorRotatorService(stack.config)
    result = svc.rotate()
    assert result.operation_succeeded, result.error
    assert result.signal_applied
    assert result.exit_changed is False  # the fake echo keeps the same exit
    assert "SIGNAL NEWNYM" in stack.control.commands


# --- health -------------------------------------------------------------------------


def test_health_all_green(tmp_path):
    report = service(tmp_path, Sequence(vr())).health()
    assert report.healthy
    assert [c.name for c in report.checks] == [
        "control",
        "bootstrap",
        "circuit_established",
        "network_liveness",
        "socks_listener",
        "exit",
    ]
    json.dumps(report.to_dict())


@pytest.mark.parametrize(
    ("status", "failing"),
    [
        (ControlStatus(True, True, bootstrap_progress=40), "bootstrap"),
        (ControlStatus(True, True, bootstrap_progress=None), "bootstrap"),
        (ControlStatus(True, True, bootstrap_progress=100, circuit_established=False), "circuit_established"),
        (ControlStatus(True, True, bootstrap_progress=100, network_liveness="down"), "network_liveness"),
        (
            ControlStatus(True, True, bootstrap_progress=100, socks_listeners=("127.0.0.1:9150",)),
            "socks_listener",
        ),
        (ControlStatus(True, True, bootstrap_progress=100, socks_listeners=()), "socks_listener"),
    ],
)
def test_health_detects_problems(tmp_path, status, failing):
    report = service(tmp_path, Sequence(vr()), control=FakeControl(status=status)).health()
    assert not report.healthy
    assert [c.name for c in report.checks if not c.ok] == [failing]


def test_health_reports_control_failure_without_masking_exit(tmp_path):
    control = FakeControl(fail=ControlError("no control"))
    report = service(tmp_path, Sequence(vr()), control=control).health()
    assert not report.healthy
    assert report.control.error == "no control"
    assert [c.name for c in report.checks] == ["control", "exit"]
    assert report.exit.ok


def test_full_stack_doctor(stack):
    stack.control.getinfo["net/listeners/socks"] = f'"127.0.0.1:{stack.socks.port}"'
    report = TorRotatorService(stack.config).health()
    assert report.healthy, report.to_dict()


@pytest.mark.parametrize(
    ("listener", "config", "expected"),
    [
        ("127.0.0.1:9050", SocksConfig(), True),
        ("127.0.0.1:9050", SocksConfig(host="localhost"), True),
        ("[::1]:9050", SocksConfig(), False),
        ("[::1]:9050", SocksConfig(host="localhost"), True),
        ("[::1]:9050", SocksConfig(host="::1"), True),
        ("[::1]:9050", SocksConfig(host="[::1]"), True),
        ("127.0.0.2:9050", SocksConfig(), False),
        ("tor:9050", SocksConfig(host="tor", allow_non_loopback=True), True),
        ("127.0.0.1:9150", SocksConfig(), False),
        ("garbage", SocksConfig(), False),
        ("unix:/run/tor/socks", SocksConfig(), False),
        ("unix:/run/tor/socks", SocksConfig(mode="unix"), True),
        ("127.0.0.1:9050", SocksConfig(mode="unix"), False),
        ("10.0.0.5:9050", SocksConfig(host="10.0.0.5", allow_non_loopback=True), True),
    ],
)
def test_listener_matching(listener, config, expected):
    assert _listener_matches(listener, config) is expected


def test_listener_matching_resolves_symlinked_unix_paths(tmp_path):
    real = tmp_path / "socks"
    real.write_text("")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert _listener_matches(f"unix:{link}", SocksConfig(mode="unix", socket_path=str(real)))


# --- watch --------------------------------------------------------------------------


class StopAfter:
    def __init__(self, svc_ref, count):
        self.svc_ref = svc_ref
        self.count = count
        self.sleeps: list[float] = []

    def __call__(self, seconds):
        self.sleeps.append(seconds)
        if len(self.sleeps) >= self.count:
            self.svc_ref[0].request_stop()


def watcher(tmp_path, verifier, control=None, stop_after=3, **sections):
    ref: list[TorRotatorService] = []
    sleeper = StopAfter(ref, stop_after)
    svc = TorRotatorService(
        offline_config(tmp_path, **sections),
        verifier=verifier,
        control_factory=lambda: control or FakeControl(),
        sleep=sleeper,
        uniform=lambda low, high: high,
    )
    ref.append(svc)
    return svc, sleeper


def test_watch_once_reports_outcome(tmp_path):
    svc, _ = watcher(tmp_path, Sequence(vr()))
    assert svc.watch(once=True) is ExitCode.OK
    svc, _ = watcher(tmp_path, Sequence(vr(), vr(ok=False)))
    assert svc.watch(once=True) is ExitCode.FAILED


def test_watch_once_busy(tmp_path):
    svc, _ = watcher(tmp_path, Sequence(vr()))
    with ProcessLock(tmp_path / "rotate.lock"):
        assert svc.watch(once=True) is ExitCode.BUSY


def test_watch_loop_runs_until_stopped_with_jitter(tmp_path):
    rotation = RotationConfig(interval_seconds=30, jitter_seconds=5, settle_seconds=0)
    svc, sleeper = watcher(tmp_path, Sequence(vr()), stop_after=3, rotation=rotation)
    assert svc.watch() is ExitCode.OK
    assert len(sleeper.sleeps) == 3
    assert all(30 < s <= 35 for s in sleeper.sleeps)
    assert svc_state(tmp_path)["counters"]["rotations_total"] == 3


def test_watch_stops_after_consecutive_failures(tmp_path):
    rotation = RotationConfig(interval_seconds=10, settle_seconds=0, max_consecutive_failures=2)
    svc, sleeper = watcher(tmp_path, Sequence(vr(), vr(ok=False)), stop_after=99, rotation=rotation)
    assert svc.watch() is ExitCode.FAILED
    interval_sleeps = [s for s in sleeper.sleeps if s > 1]  # excludes zero-length retry delays
    assert len(interval_sleeps) == 1


def test_watch_survives_errors_and_busy_lock(tmp_path, monkeypatch):
    svc, sleeper = watcher(tmp_path, Sequence(vr()), stop_after=4)
    outcomes = iter([LockBusyError("busy"), ControlError("boom"), RuntimeError("bug"), None])
    real_rotate = svc.rotate

    def flaky():
        outcome = next(outcomes)
        if outcome is not None:
            raise outcome
        return real_rotate()

    monkeypatch.setattr(svc, "rotate", flaky)
    assert svc.watch() is ExitCode.OK
    assert len(sleeper.sleeps) == 4


def test_watch_os_error_counts_as_failure(tmp_path, monkeypatch):
    rotation = RotationConfig(interval_seconds=10, settle_seconds=0, max_consecutive_failures=1)
    svc, _ = watcher(tmp_path, Sequence(vr()), rotation=rotation)
    monkeypatch.setattr(svc, "rotate", lambda: (_ for _ in ()).throw(OSError("disk")))
    assert svc.watch() is ExitCode.FAILED


def test_watch_does_not_start_when_already_stopped(tmp_path):
    svc, sleeper = watcher(tmp_path, Sequence(vr()))
    svc.request_stop()
    assert svc.watch() is ExitCode.OK
    assert sleeper.sleeps == []


def test_unix_socket_full_stack(short_tmp, echo, ca_file):
    from fakes import FakeSocks
    from tor_rotator.config import AppConfig

    control_dir = short_tmp / "c"
    socks_dir = short_tmp / "s"
    control_dir.mkdir()
    socks_dir.mkdir()
    with (
        FakeTorControl(control_dir, unix=True) as control,
        FakeSocks(socks_dir, unix=True, upstream=echo.address) as socks,
    ):
        control.getinfo["net/listeners/socks"] = f'"unix:{socks.socket_path}"'
        config = AppConfig(
            control=control.control_config(),
            socks=socks.socks_config(),
            verify=VerifyConfig(ca_file=ca_file, timeout_seconds=5, attempts_after_rotation=1),
            rotation=RotationConfig(interval_seconds=10, settle_seconds=0),
            runtime=runtime_for(short_tmp),
        )
        svc = TorRotatorService(config)
        assert svc.health().healthy
        assert svc.rotate().operation_succeeded
    assert os.path.exists(short_tmp / "state.json")


class Raising:
    def __init__(self, exc):
        self.exc = exc

    def verify(self):
        raise self.exc


def test_controlled_verifier_errors_are_persisted_as_failures(tmp_path):
    from tor_rotator.errors import ProbeError

    svc = service(tmp_path, Raising(ProbeError("trust store vanished")))
    result = svc.rotate()
    assert not result.operation_succeeded
    assert "verification could not run" in (result.before.error or "")
    assert svc_state(tmp_path)["counters"]["rotations_failed"] == 1
    assert not service(tmp_path, Raising(OSError("disk"))).health().healthy


def test_default_verifier_observes_stop_requests(tmp_path):
    svc = TorRotatorService(offline_config(tmp_path), control_factory=FakeControl)
    svc.request_stop()
    result = svc.verifier.verify()
    assert not result.ok
    assert all(o.error == "cancelled: stop requested" for o in result.observations)
