"""Crash-safe persisted state: last rotation, counters and failure streak.

Writes are atomic: data goes to a temporary file in the same directory, is fsynced,
then ``rename(2)``-d over the target, and the directory is fsynced. A crash at any
point leaves either the old or the new file, never a torn one.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Final

from .errors import StateError
from .models import RotationResult

SCHEMA_VERSION: Final = 2
MAX_STATE_BYTES: Final = 4 * 1024 * 1024
_COUNTER_KEYS: Final = ("rotations_total", "rotations_succeeded", "rotations_failed", "exit_changes_total")


def atomic_write_text(path: Path, text: str, *, mode: int) -> None:
    """Atomically replace *path* with *text*, leaving it with permissions *mode*."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise
    _fsync_directory(parent)


def _fsync_directory(directory: Path) -> None:
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:  # pragma: no cover - platforms without directory fds
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - some filesystems reject directory fsync
        pass
    finally:
        os.close(dir_fd)


class StateStore:
    """JSON state file with atomic replacement and strict reads."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def read(self) -> dict[str, Any] | None:
        """Return the stored mapping, ``None`` if absent; raise :class:`StateError` if corrupt."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StateError(f"cannot open state file {self.path}: {exc.strerror or exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StateError(f"state file {self.path} is not a regular file")
            with os.fdopen(os.dup(fd), "rb") as handle:
                raw = handle.read(MAX_STATE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_STATE_BYTES:
            raise StateError(f"state file {self.path} exceeds {MAX_STATE_BYTES} bytes")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise StateError(f"state file {self.path} is corrupt: {exc}") from exc
        if not isinstance(data, dict):
            raise StateError(f"state file {self.path} does not contain a JSON object")
        return data

    def write(self, payload: dict[str, Any]) -> None:
        """Atomically replace the state file (mode 0640)."""
        text = json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
        atomic_write_text(self.path, text, mode=0o640)


def _counter(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def record_rotation(previous: dict[str, Any] | None, result: RotationResult) -> dict[str, Any]:
    """Fold *result* into the previous state snapshot and return the new snapshot.

    State written by 1.x (only ``last_rotation``) is accepted; missing or malformed
    counters start from zero.
    """
    prior = previous or {}
    prior_counters = prior.get("counters")
    counters = {
        key: _counter(prior_counters.get(key)) if isinstance(prior_counters, dict) else 0
        for key in _COUNTER_KEYS
    }
    succeeded = result.operation_succeeded
    counters["rotations_total"] += 1
    counters["rotations_succeeded" if succeeded else "rotations_failed"] += 1
    if result.successful_change:
        counters["exit_changes_total"] += 1

    last_success = prior.get("last_success_at")
    return {
        "schema_version": SCHEMA_VERSION,
        "counters": counters,
        "consecutive_failures": 0 if succeeded else _counter(prior.get("consecutive_failures")) + 1,
        "last_success_at": result.completed_at
        if succeeded
        else (last_success if isinstance(last_success, str) else None),
        "last_rotation": result.to_dict(),
    }
