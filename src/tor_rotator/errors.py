"""Error hierarchy and process exit codes.

Every controlled failure raised by this package derives from :class:`TorRotatorError`
and carries the process exit code the CLI reports for it. Anything that is *not* a
``TorRotatorError`` is treated as a programming error.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable, documented process exit codes."""

    OK = 0
    """The operation ran and met its configured success policy."""

    FAILED = 1
    """The operation ran but did not meet its success policy (result is still emitted)."""

    USAGE = 2
    """Invalid command-line usage (reported by argparse)."""

    CONFIG = 3
    """The configuration file is missing, unreadable, malformed, or unsafe."""

    RUNTIME = 4
    """A runtime failure prevented the operation from producing a result."""

    BUSY = 5
    """Another rotation holds the rotation lock; nothing was changed."""

    INTERRUPTED = 130
    """Interrupted by SIGINT before completion."""


class TorRotatorError(RuntimeError):
    """Base class for all controlled failures."""

    exit_code: ExitCode = ExitCode.RUNTIME


class ConfigurationError(TorRotatorError):
    """Configuration is invalid or unsafe."""

    exit_code = ExitCode.CONFIG


class ControlError(TorRotatorError):
    """The Tor control interface could not be used safely."""


class ControlCommandError(ControlError):
    """Tor answered a control command with a non-success status code."""

    def __init__(self, code: int, detail: str) -> None:
        super().__init__(f"Tor control command failed ({code}): {detail}")
        self.code = code


class ControlTimeoutError(ControlError):
    """Tor did not answer on the control connection within the allotted time."""


class ProxyError(TorRotatorError):
    """The SOCKS5 proxy refused or failed a request."""


class ProbeError(TorRotatorError):
    """An HTTPS verification probe failed."""


class ProbeTimeoutError(ProbeError):
    """An HTTPS verification probe exceeded its total deadline."""


class LockBusyError(TorRotatorError):
    """Another process already holds the rotation lock."""

    exit_code = ExitCode.BUSY


class StateError(TorRotatorError):
    """Persisted state could not be read or written safely."""
