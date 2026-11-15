"""Single-writer inter-process lock for rotations, backed by ``flock(2)``.

An advisory ``flock`` is released by the kernel when the holder exits, crashes or is
killed, so there is no stale-pidfile problem to recover from.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType

from .errors import LockBusyError, TorRotatorError


class ProcessLock:
    """Non-blocking exclusive lock held for the lifetime of the context."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def __enter__(self) -> ProcessLock:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o640)
        except OSError as exc:
            raise TorRotatorError(f"cannot open rotation lock {self.path}: {exc.strerror or exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise LockBusyError(f"another rotation process already holds {self.path}") from exc
        except OSError as exc:
            os.close(fd)
            raise TorRotatorError(f"cannot lock {self.path}: {exc.strerror or exc}") from exc
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
        except OSError:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)  # closing the descriptor releases the flock
