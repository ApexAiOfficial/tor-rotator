from __future__ import annotations

import io
import json
import logging
import os

import pytest

from fakes import EXIT_A, EXIT_B
from tor_rotator.errors import LockBusyError, StateError, TorRotatorError
from tor_rotator.lock import ProcessLock
from tor_rotator.log import JsonFormatter, configure_logging
from tor_rotator.metrics import render, write
from tor_rotator.models import RotationResult, VerificationResult
from tor_rotator.state import MAX_STATE_BYTES, StateStore, atomic_write_text, record_rotation


def vr(ip, ok=True):
    return VerificationResult(ok=ok, ip=ip if ok else None, tor_confirmed=ok or None, quorum=2, agreeing=2)


def rotation(success=True, changed=True):
    return RotationResult(
        request_id="r",
        requested_at="2026-11-15T00:00:00.000+00:00",
        completed_at="2026-11-15T00:00:05.000+00:00",
        signal_accepted=True,
        signal_applied=success,
        before=vr(EXIT_A),
        after=vr(EXIT_B if changed else EXIT_A),
        exit_changed=changed,
        verified=True,
        attempts=1,
        duration_ms=5000,
    )


# --- state ----------------------------------------------------------------------------


def test_state_round_trip_permissions_and_no_temp_leftovers(tmp_path):
    store = StateStore(tmp_path / "nested" / "state.json")
    assert store.read() is None
    store.write({"x": 1})
    assert store.read() == {"x": 1}
    assert store.path.stat().st_mode & 0o777 == 0o640
    assert [p.name for p in store.path.parent.iterdir()] == ["state.json"]


@pytest.mark.parametrize(
    ("content", "message"),
    [(b"{oops", "corrupt"), (b"[1, 2]", "JSON object"), (b"\xff", "corrupt"), (b"[" * 200_000, "corrupt")],
)
def test_state_read_rejects_bad_content(tmp_path, content, message):
    path = tmp_path / "state.json"
    path.write_bytes(content)
    with pytest.raises(StateError, match=message):
        StateStore(path).read()


def test_state_read_rejects_oversize_symlink_and_directory(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (MAX_STATE_BYTES + 1))
    with pytest.raises(StateError, match="exceeds"):
        StateStore(big).read()
    link = tmp_path / "link.json"
    link.symlink_to(big)
    with pytest.raises(StateError, match="cannot open"):
        StateStore(link).read()
    with pytest.raises(StateError, match="not a regular file"):
        StateStore(tmp_path).read()


def test_atomic_write_cleans_up_on_failure(tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="replace failed"):
        atomic_write_text(tmp_path / "f", "data", mode=0o600)
    assert list(tmp_path.iterdir()) == []


def test_record_rotation_from_nothing_and_from_1x_state():
    first = record_rotation(None, rotation())
    assert first["schema_version"] == 2
    assert first["counters"] == {
        "rotations_total": 1,
        "rotations_succeeded": 1,
        "rotations_failed": 0,
        "exit_changes_total": 1,
    }
    legacy = record_rotation({"last_rotation": {"x": 1}}, rotation(changed=False))
    assert legacy["counters"]["exit_changes_total"] == 0


def test_record_rotation_tolerates_malformed_counters_and_tracks_streaks():
    malformed = {
        "counters": {"rotations_total": "many", "rotations_failed": -3},
        "consecutive_failures": True,
    }
    failed = record_rotation(malformed, rotation(success=False))
    assert failed["counters"]["rotations_total"] == 1
    assert failed["counters"]["rotations_failed"] == 1
    assert failed["consecutive_failures"] == 1
    assert failed["last_success_at"] is None
    again = record_rotation(
        failed | {"last_success_at": "2026-01-01T00:00:00+00:00"}, rotation(success=False)
    )
    assert again["consecutive_failures"] == 2
    assert again["last_success_at"] == "2026-01-01T00:00:00+00:00"
    recovered = record_rotation(again, rotation())
    assert recovered["consecutive_failures"] == 0
    assert recovered["last_success_at"] == rotation().completed_at


# --- metrics --------------------------------------------------------------------------


def test_metrics_render_empty_state():
    text = render(None)
    assert "tor_rotator_build_info{version=" in text
    assert 'tor_rotator_rotations_total{outcome="succeeded"} 0' in text
    assert "tor_rotator_last_rotation_timestamp_seconds" not in text
    assert text.endswith("\n")


def test_metrics_render_full_state_without_ip_addresses():
    state = record_rotation(None, rotation())
    text = render(state)
    assert "tor_rotator_last_rotation_success 1" in text
    assert "tor_rotator_last_rotation_exit_changed 1" in text
    assert "tor_rotator_last_rotation_duration_seconds 5" in text
    assert "tor_rotator_exit_verified 1" in text
    assert "tor_rotator_last_rotation_timestamp_seconds 1794700805" in text
    assert EXIT_A not in text and EXIT_B not in text
    for line in text.splitlines():
        if not line.startswith("#"):
            name, value = line.rsplit(" ", 1)
            float(value)


def test_metrics_skip_unparseable_values():
    text = render(
        {
            "counters": "bad",
            "last_success_at": "not-a-date",
            "last_rotation": {"completed_at": "2026-11-15T00:00:00", "duration_ms": 1500.5, "after": "x"},
        }
    )
    assert "tor_rotator_last_success_timestamp_seconds" not in text
    assert "tor_rotator_last_rotation_timestamp_seconds" not in text  # naive timestamps are ignored
    assert "tor_rotator_last_rotation_duration_seconds 1.5005" in text


def test_metrics_write(tmp_path):
    write(tmp_path / "m.prom", "x 1\n")
    assert (tmp_path / "m.prom").read_text() == "x 1\n"
    assert (tmp_path / "m.prom").stat().st_mode & 0o777 == 0o644


# --- lock -----------------------------------------------------------------------------


def test_lock_is_exclusive_and_released(tmp_path):
    path = tmp_path / "locks" / "rotate.lock"
    with ProcessLock(path):
        assert path.read_text().strip() == str(os.getpid())
        assert path.stat().st_mode & 0o777 == 0o600
        with pytest.raises(LockBusyError, match="another rotation"):
            ProcessLock(path).__enter__()
    with ProcessLock(path):
        pass


def test_lock_open_and_flock_failures(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(TorRotatorError, match="cannot open rotation lock"):
        ProcessLock(blocker / "rotate.lock").__enter__()
    link = tmp_path / "link.lock"
    link.symlink_to(tmp_path / "target")
    with pytest.raises(TorRotatorError, match="cannot open rotation lock"):
        ProcessLock(link).__enter__()

    import fcntl

    def denied(fd, op):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(fcntl, "flock", denied)
    with pytest.raises(TorRotatorError, match="cannot lock"):
        ProcessLock(tmp_path / "x.lock").__enter__()


def test_lock_write_failure_closes_descriptor(tmp_path, monkeypatch):
    def fail(fd, length):
        raise OSError("ftruncate failed")

    monkeypatch.setattr(os, "ftruncate", fail)
    with pytest.raises(OSError, match="ftruncate"):
        ProcessLock(tmp_path / "x.lock").__enter__()
    monkeypatch.undo()
    with ProcessLock(tmp_path / "x.lock"):
        pass


# --- logging --------------------------------------------------------------------------


def test_json_formatter():
    record = logging.LogRecord("tor_rotator", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
    record.request_id = "abc"
    record._private = "hidden"
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello world"
    assert payload["request_id"] == "abc"
    assert payload["level"] == "WARNING"
    assert payload["timestamp"].endswith("+00:00")
    assert "_private" not in payload


def test_json_formatter_includes_exceptions():
    try:
        raise ValueError("bad")
    except ValueError:
        import sys

        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: bad" in payload["exception"]


def test_configure_logging_replaces_handlers_and_writes_to_stream():
    stream = io.StringIO()
    configure_logging("debug", "text", stream=stream)
    configure_logging("info", "json", stream=stream)
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert root.level == logging.INFO
    logging.getLogger("tor_rotator").info("event", extra={"k": 1})
    assert json.loads(stream.getvalue().splitlines()[-1])["k"] == 1
