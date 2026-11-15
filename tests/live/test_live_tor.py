"""Live tests against a real Tor client and the Tor network.

Opt-in only: run through ``scripts/live-tor.sh``, which starts a private Tor instance and
exports the ``TOR_ROTATOR_LIVE_*`` variables these tests read.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from tor_rotator.config import (
    AppConfig,
    ControlConfig,
    RotationConfig,
    RuntimeConfig,
    SocksConfig,
    VerifyConfig,
)
from tor_rotator.control import TorControlClient
from tor_rotator.service import TorRotatorService

LIVE_DIR = os.environ.get("TOR_ROTATOR_LIVE_DIR")
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE_DIR, reason="run via scripts/live-tor.sh"),
    pytest.mark.timeout(300),
]


def make_config(
    tmp_path: Path, *, control_mode: str = "tcp", socks_mode: str = "tcp", auth: str = "safecookie"
):
    assert LIVE_DIR
    password = {"password_env": "TOR_ROTATOR_LIVE_PASSWORD"} if auth == "hashedpassword" else {}
    cookie = {"cookie_path": f"{LIVE_DIR}/control.authcookie"} if auth == "safecookie" else {}
    return AppConfig(
        control=ControlConfig(
            mode=control_mode,  # type: ignore[arg-type]
            port=int(os.environ["TOR_ROTATOR_LIVE_CONTROL_PORT"]),
            socket_path=f"{LIVE_DIR}/control",
            auth=auth,  # type: ignore[arg-type]
            **password,
            **cookie,
        ),
        socks=SocksConfig(
            mode=socks_mode,  # type: ignore[arg-type]
            port=int(os.environ["TOR_ROTATOR_LIVE_SOCKS_PORT"]),
            socket_path=f"{LIVE_DIR}/socks",
        ),
        verify=VerifyConfig(timeout_seconds=40, attempts_after_rotation=4, retry_delay_seconds=3),
        rotation=RotationConfig(interval_seconds=10, settle_seconds=1),
        runtime=RuntimeConfig(
            state_file=str(tmp_path / "state.json"),
            lock_file=str(tmp_path / "rotate.lock"),
            metrics_file=str(tmp_path / "tor_rotator.prom"),
            log_format="text",
        ),
    )


@pytest.mark.parametrize(
    ("control_mode", "socks_mode", "auth"),
    [("tcp", "tcp", "safecookie"), ("unix", "unix", "safecookie"), ("tcp", "unix", "hashedpassword")],
)
def test_doctor(tmp_path, control_mode, socks_mode, auth):
    report = TorRotatorService(
        make_config(tmp_path, control_mode=control_mode, socks_mode=socks_mode, auth=auth)
    ).health()
    print(json.dumps(report.to_dict(), indent=2))
    assert report.healthy, [c for c in report.checks if not c.ok]
    assert report.control.tor_version
    assert report.exit.tor_confirmed is True


def test_verify_is_unanimous_and_tor_confirmed(tmp_path):
    result = TorRotatorService(make_config(tmp_path)).verify()
    print(json.dumps(result.to_dict(), indent=2))
    assert result.ok, result.error
    assert result.dissenting == 0
    assert result.agreeing == 3


def test_rotate_and_watch_once(tmp_path):
    service = TorRotatorService(make_config(tmp_path))
    result = service.rotate()
    print(json.dumps(result.to_dict(), indent=2))
    assert result.operation_succeeded, result.error
    assert result.signal_confirmation_ms is not None
    assert result.signal_confirmation_ms < 2000
    time.sleep(11)  # stay clear of Tor's NEWNYM rate limit
    assert service.watch(once=True) == 0
    metrics = (tmp_path / "tor_rotator.prom").read_text()
    assert 'tor_rotator_rotations_total{outcome="succeeded"} 2' in metrics


def test_rate_limited_newnym_is_deferred_then_confirmed(tmp_path):
    config = make_config(tmp_path)
    with TorControlClient(config.control) as tor:
        first = tor.signal_newnym()
    with TorControlClient(config.control) as tor:
        second = tor.signal_newnym()
    print(first, second, sep="\n")
    assert first.applied
    # Tor defers a NEWNYM sent within 10 s of the previous one and emits the SIGNAL event
    # when it finally applies it; the 12 s default window observes that confirmation.
    assert second.applied
    assert second.confirmation_seconds is not None
    assert second.confirmation_seconds > 5


def test_short_event_window_reports_deferral_honestly(tmp_path):
    short = replace(make_config(tmp_path).control, signal_event_timeout_seconds=2.0)
    time.sleep(11)
    with TorControlClient(short) as tor:
        assert tor.signal_newnym().applied
    with TorControlClient(short) as tor:
        deferred = tor.signal_newnym()
    assert deferred.accepted
    assert not deferred.applied
    assert "rate limit" in (deferred.detail or "")


def test_exit_ip_changes_within_a_few_rotations(tmp_path):
    service = TorRotatorService(make_config(tmp_path))
    changed = False
    for _ in range(3):
        time.sleep(11)
        result = service.rotate()
        assert result.operation_succeeded, result.error
        if result.successful_change:
            changed = True
            break
    assert changed, "three verified rotations never moved to a different exit"


def test_cli_end_to_end(tmp_path):
    assert LIVE_DIR
    config = tmp_path / "config.toml"
    config.write_text(
        f"""
[control]
mode = "unix"
socket_path = "{LIVE_DIR}/control"
auth = "safecookie"
cookie_path = "{LIVE_DIR}/control.authcookie"

[socks]
mode = "unix"
socket_path = "{LIVE_DIR}/socks"

[verify]
timeout_seconds = 40

[runtime]
state_file = "{tmp_path}/state.json"
lock_file = "{tmp_path}/rotate.lock"
log_format = "json"
"""
    )
    config.chmod(0o600)
    time.sleep(11)
    for command, expected in (("doctor", 0), ("verify", 0), ("rotate", 0), ("status", 0)):
        proc = subprocess.run(
            [sys.executable, "-m", "tor_rotator", "--config", str(config), command],
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
        assert proc.returncode == expected, (command, proc.stdout, proc.stderr)
        json.loads(proc.stdout)
