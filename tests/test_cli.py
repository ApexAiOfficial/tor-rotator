from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading

import pytest

from fakes import EXIT_A
from tor_rotator import __version__
from tor_rotator.cli import build_parser, main
from tor_rotator.errors import ExitCode
from tor_rotator.lock import ProcessLock
from tor_rotator.service import TorRotatorService


def toml_for(stack) -> str:
    c, s, rt = stack.config.control, stack.config.socks, stack.config.runtime
    return f"""
[control]
mode = "tcp"
host = "127.0.0.1"
port = {c.port}
connect_timeout_seconds = 3
signal_event_timeout_seconds = 1

[socks]
host = "127.0.0.1"
port = {s.port}

[verify]
ca_file = "{stack.config.verify.ca_file}"
timeout_seconds = 5
attempts_after_rotation = 1

[rotation]
interval_seconds = 10
settle_seconds = 0

[runtime]
state_file = "{rt.state_file}"
lock_file = "{rt.lock_file}"
log_format = "json"
log_level = "INFO"
"""


@pytest.fixture
def cfg(stack, short_tmp):
    path = short_tmp / "config.toml"
    path.write_text(toml_for(stack))
    path.chmod(0o640)
    return str(path)


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_version(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_usage_error_exit_code(capsys):
    with pytest.raises(SystemExit) as info:
        main(["frobnicate"])
    assert info.value.code == ExitCode.USAGE


def test_help_documents_exit_codes():
    assert "exit codes" in build_parser().format_help()


def test_config_command_prints_redacted_effective_config(capsys, cfg):
    code, out, _ = run(capsys, "--config", cfg, "--pretty", "config")
    assert code == ExitCode.OK
    data = json.loads(out)
    assert data["ok"] is True
    assert data["config"]["socks"]["probe_password"] == "<redacted>"


def test_config_error_is_exit_3_with_json_on_stderr(capsys, tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text('[control]\nhost = "0.0.0.0"\n')
    code, out, err = run(capsys, "--config", str(path), "status")
    assert code == ExitCode.CONFIG
    assert out == ""
    payload = json.loads(err)
    assert payload == {
        "ok": False,
        "error": "refusing non-loopback Tor ControlPort host",
        "error_type": "ConfigurationError",
        "exit_code": 3,
    }


def test_config_from_environment(capsys, cfg, monkeypatch):
    monkeypatch.setenv("TOR_ROTATOR_CONFIG", cfg)
    code, out, _ = run(capsys, "config")
    assert code == ExitCode.OK


def test_status_without_state(capsys, cfg):
    code, out, _ = run(capsys, "--config", cfg, "status")
    assert code == ExitCode.FAILED
    assert json.loads(out)["state"] is None


def test_verify_rotate_status_metrics_full_stack(capsys, cfg, stack):
    code, out, err = run(capsys, "--config", cfg, "verify")
    assert code == ExitCode.OK, err
    assert json.loads(out)["ip"] == EXIT_A

    code, out, err = run(capsys, "--config", cfg, "rotate")
    assert code == ExitCode.OK, err
    rotation = json.loads(out)
    assert rotation["signal_applied"] is True and rotation["operation_succeeded"] is True
    # logs are JSON lines on stderr, never mixed into stdout
    assert any(json.loads(line)["message"] == "rotation completed" for line in err.splitlines())

    code, out, _ = run(capsys, "--config", cfg, "status")
    assert code == ExitCode.OK
    assert json.loads(out)["counters"]["rotations_total"] == 1

    code, out, _ = run(capsys, "--config", cfg, "metrics")
    assert code == ExitCode.OK
    assert 'tor_rotator_rotations_total{outcome="succeeded"} 1' in out


def test_doctor_full_stack(capsys, cfg, stack):
    stack.control.getinfo["net/listeners/socks"] = f'"127.0.0.1:{stack.socks.port}"'
    code, out, err = run(capsys, "--config", cfg, "--pretty", "doctor")
    assert code == ExitCode.OK, out
    assert json.loads(out)["healthy"] is True


def test_doctor_unhealthy_is_exit_1(capsys, cfg, stack):
    code, out, _ = run(capsys, "--config", cfg, "doctor")  # SOCKS listener mismatch
    assert code == ExitCode.FAILED
    failing = [c["name"] for c in json.loads(out)["checks"] if not c["ok"]]
    assert failing == ["socks_listener"]


def test_verify_failure_is_exit_1(capsys, cfg, stack):
    stack.echo.answer(torproject=(EXIT_A, False))
    code, out, _ = run(capsys, "--config", cfg, "verify")
    assert code == ExitCode.FAILED
    assert json.loads(out)["tor_confirmed"] is False


def test_rotate_failure_is_exit_1(capsys, cfg, stack):
    stack.control.newnym = "ignored"
    code, out, _ = run(capsys, "--config", cfg, "rotate")
    assert code == ExitCode.FAILED
    assert json.loads(out)["signal_applied"] is False


def test_rotate_lock_busy_is_exit_5(capsys, cfg, stack):
    with ProcessLock(stack.config.runtime.lock_file):
        code, _, err = run(capsys, "--config", cfg, "rotate")
    assert code == ExitCode.BUSY
    assert json.loads(err)["error_type"] == "LockBusyError"


def test_corrupt_state_is_exit_4(capsys, cfg, stack):
    with open(stack.config.runtime.state_file, "w") as handle:
        handle.write("{")
    code, _, err = run(capsys, "--config", cfg, "status")
    assert code == ExitCode.RUNTIME
    assert json.loads(err)["error_type"] == "StateError"


def test_watch_once(capsys, cfg):
    code, _, _ = run(capsys, "--config", cfg, "watch", "--once")
    assert code == ExitCode.OK


def test_log_level_override(capsys, cfg):
    code, _, err = run(capsys, "--config", cfg, "--log-level", "error", "rotate")
    assert code == ExitCode.OK
    assert err == ""


def test_watch_stops_gracefully_on_sigterm(capsys, cfg, monkeypatch):
    original_wait = TorRotatorService.watch

    def watch_then_signal(self, *, once=False):
        threading.Timer(0.2, os.kill, args=(os.getpid(), signal.SIGTERM)).start()
        return original_wait(self, once=once)

    monkeypatch.setattr(TorRotatorService, "watch", watch_then_signal)
    before = signal.getsignal(signal.SIGTERM)
    code, _, err = run(capsys, "--config", cfg, "watch")
    assert code == ExitCode.OK
    assert "stop requested" in err
    assert signal.getsignal(signal.SIGTERM) is before


def test_second_signal_interrupts(capsys, cfg, monkeypatch):
    def watch_blocking(self, *, once=False):
        self.request_stop()
        os.kill(os.getpid(), signal.SIGINT)
        raise AssertionError("signal handler should have interrupted")

    monkeypatch.setattr(TorRotatorService, "watch", watch_blocking)
    code, _, _ = run(capsys, "--config", cfg, "watch")
    assert code == ExitCode.INTERRUPTED


def test_unexpected_exception_keeps_json_contract(capsys, cfg, monkeypatch):
    monkeypatch.setattr(TorRotatorService, "verify", lambda self: 1 / 0)
    code, _, err = run(capsys, "--config", cfg, "verify")
    assert code == ExitCode.RUNTIME
    payload = json.loads(err.strip().splitlines()[-1])
    assert payload["error_type"] == "ZeroDivisionError"


def test_os_error_is_runtime_exit(capsys, cfg, monkeypatch):
    def fail(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(TorRotatorService, "verify", fail)
    code, _, err = run(capsys, "--config", cfg, "verify")
    assert code == ExitCode.RUNTIME
    assert json.loads(err)["error_type"] == "PermissionError"


def test_module_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "tor_rotator", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"tor-rotator {__version__}"
