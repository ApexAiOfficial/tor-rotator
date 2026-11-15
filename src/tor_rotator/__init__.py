"""Tor Rotator: verified Tor circuit rotation.

Tor Rotator asks a running Tor daemon for clean circuits (``SIGNAL NEWNYM``) over the
authenticated Tor Control Protocol, then independently verifies the resulting exit
through Tor with a multi-provider quorum. It treats control-plane success and
exit verification as separate facts and never reports one as the other.
"""

from __future__ import annotations

from ._version import __version__
from .config import AppConfig
from .errors import (
    ConfigurationError,
    ControlError,
    ExitCode,
    LockBusyError,
    ProbeError,
    ProxyError,
    StateError,
    TorRotatorError,
)
from .models import (
    ControlStatus,
    HealthCheck,
    HealthReport,
    NewnymOutcome,
    ProviderObservation,
    RotationResult,
    VerificationResult,
)
from .service import TorRotatorService
from .verify import ExitVerifier

__all__ = [
    "AppConfig",
    "ConfigurationError",
    "ControlError",
    "ControlStatus",
    "ExitCode",
    "ExitVerifier",
    "HealthCheck",
    "HealthReport",
    "LockBusyError",
    "NewnymOutcome",
    "ProbeError",
    "ProviderObservation",
    "ProxyError",
    "RotationResult",
    "StateError",
    "TorRotatorError",
    "TorRotatorService",
    "VerificationResult",
    "__version__",
]
