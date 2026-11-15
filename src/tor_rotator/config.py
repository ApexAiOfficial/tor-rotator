"""Typed TOML configuration with strict type checking and explicit safety validation.

Loading is a two-step process:

1. :meth:`AppConfig.from_mapping` builds the configuration from a parsed TOML mapping and
   rejects unknown keys and wrongly-typed values (``port = "9051"``, ``port = true``,
   ``timeout = nan`` ...). TOML has no ``null``, so optional keys are simply omitted.
2. :meth:`AppConfig.validate` enforces semantic and security policy (loopback-only control
   plane, no plaintext secrets, a quorum that is actually satisfiable, and so on).

:meth:`AppConfig.load` performs both steps and additionally refuses unsafe config files.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import stat
import tomllib
import types
import typing
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Final, Literal, TypeVar, get_type_hints
from urllib.parse import urlsplit

from .errors import ConfigurationError

CONFIG_ENV_VAR: Final = "TOR_ROTATOR_CONFIG"
"""Environment variable consulted when no ``--config`` path is given."""

MAX_CONFIG_BYTES: Final = 1024 * 1024
MAX_SECRET_BYTES: Final = 4096
_CREDENTIALS_PREFIXES: Final = ("${CREDENTIALS_DIRECTORY}/", "$CREDENTIALS_DIRECTORY/")
_ENV_NAME_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROVIDER_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_JSON_FIELD_RE: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

BUILTIN_PROVIDERS: Final = frozenset({"torproject", "ipify", "icanhazip", "aws"})
TOR_AUTHORITY_PROVIDERS: Final = frozenset({"torproject"})

ControlMode = Literal["tcp", "unix"]
SocksMode = Literal["tcp", "unix"]
AuthMethod = Literal["auto", "safecookie", "hashedpassword", "null"]
LogFormat = Literal["json", "text"]
ProviderFormat = Literal["text", "json"]

_LOG_LEVELS: Final = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ControlConfig:
    """How to reach and authenticate to Tor's control interface."""

    mode: ControlMode = "tcp"
    host: str = "127.0.0.1"
    port: int = 9051
    socket_path: str = "/run/tor/control"
    auth: AuthMethod = "auto"
    cookie_path: str | None = None
    password_env: str | None = None
    password_file: str | None = None
    allow_null_auth: bool = False
    connect_timeout_seconds: float = 5.0
    # Tor rate-limits NEWNYM to one application every 10 seconds and *defers* (rather than
    # drops) a rate-limited request. Waiting slightly longer than that window lets a deferred
    # NEWNYM still be confirmed; a confirmation that arrives promptly returns immediately.
    signal_event_timeout_seconds: float = 12.0


@dataclass(frozen=True, slots=True)
class SocksConfig:
    """The Tor SOCKS listener used for verification probes."""

    mode: SocksMode = "tcp"
    host: str = "127.0.0.1"
    port: int = 9050
    socket_path: str = "/run/tor/socks"
    # A stable credential pair: Tor isolates streams by SOCKS credentials
    # (IsolateSOCKSAuth is on by default), so probes share one circuit with each other
    # and never with applications. These values are isolation labels, not secrets.
    probe_username: str = "tor-rotator-probe"
    probe_password: str = "fixed-probe-isolation"  # noqa: S105 - isolation label, not a secret
    allow_non_loopback: bool = False


@dataclass(frozen=True, slots=True)
class CustomProvider:
    """A user-supplied HTTPS IP-echo endpoint (for example a self-hosted one)."""

    name: str
    url: str
    format: ProviderFormat = "text"
    json_field: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyConfig:
    """Exit verification policy."""

    quorum: int = 2
    require_unanimous: bool = True
    require_tor_confirmation: bool = True
    timeout_seconds: float = 15.0
    attempts_after_rotation: int = 4
    retry_delay_seconds: float = 2.0
    # Sampling rounds per verification when providers disagree (see consensus.resample).
    max_rounds: int = 3
    providers: tuple[str, ...] = ("torproject", "ipify", "icanhazip")
    ca_file: str | None = None
    custom_providers: tuple[CustomProvider, ...] = ()


@dataclass(frozen=True, slots=True)
class RotationConfig:
    """Rotation and scheduling policy."""

    interval_seconds: float = 600.0
    jitter_seconds: float = 0.0
    settle_seconds: float = 1.0
    require_exit_change: bool = False
    max_consecutive_failures: int = 0


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Local runtime paths and logging."""

    state_file: str = "/var/lib/tor-rotator/state.json"
    lock_file: str = "/var/lib/tor-rotator/rotate.lock"
    metrics_file: str | None = None
    log_format: LogFormat = "json"
    log_level: str = "INFO"


_SECTIONS: Final[dict[str, type[Any]]] = {
    "control": ControlConfig,
    "socks": SocksConfig,
    "verify": VerifyConfig,
    "rotation": RotationConfig,
    "runtime": RuntimeConfig,
}
_FORBIDDEN_CONTROL_KEYS: Final = frozenset({"password", "control_password", "cookie"})


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Complete, immutable application configuration."""

    control: ControlConfig = field(default_factory=ControlConfig)
    socks: SocksConfig = field(default_factory=SocksConfig)
    verify: VerifyConfig = field(default_factory=VerifyConfig)
    rotation: RotationConfig = field(default_factory=RotationConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> AppConfig:
        """Load, type-check and validate configuration.

        With no *path*, ``$TOR_ROTATOR_CONFIG`` is consulted; with neither, built-in defaults
        are used.
        """
        if path is None:
            env_path = os.environ.get(CONFIG_ENV_VAR)
            path = env_path or None
        config = cls() if path is None else cls.from_mapping(_read_config_file(Path(path)))
        config.validate()
        return config

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> AppConfig:
        """Build a configuration from a parsed TOML mapping (type checks only)."""
        if not isinstance(raw, dict):
            raise ConfigurationError("configuration root must be a table")
        unknown = sorted(set(raw) - set(_SECTIONS))
        if unknown:
            raise ConfigurationError(f"unknown config sections: {unknown}")

        control_raw = _table(raw.get("control", {}), "control")
        if _FORBIDDEN_CONTROL_KEYS & set(control_raw):
            raise ConfigurationError(
                "control secrets must not be stored in TOML; "
                "use password_env, password_file or Tor cookie authentication"
            )

        verify_raw = dict(_table(raw.get("verify", {}), "verify"))
        custom = _custom_providers(verify_raw.pop("custom_providers", {}))
        verify = replace(_build(VerifyConfig, verify_raw, "verify"), custom_providers=custom)

        return cls(
            control=_build(ControlConfig, control_raw, "control"),
            socks=_build(SocksConfig, _table(raw.get("socks", {}), "socks"), "socks"),
            verify=verify,
            rotation=_build(RotationConfig, _table(raw.get("rotation", {}), "rotation"), "rotation"),
            runtime=_build(RuntimeConfig, _table(raw.get("runtime", {}), "runtime"), "runtime"),
        )

    # --------------------------------------------------------------- validation

    def validate(self) -> None:
        """Enforce semantic and security policy. Raises :class:`ConfigurationError`."""
        self._validate_control()
        self._validate_socks()
        self._validate_verify()
        self._validate_rotation()
        self._validate_runtime()

    def _validate_control(self) -> None:
        c = self.control
        _require(c.mode in {"tcp", "unix"}, "control.mode must be 'tcp' or 'unix'")
        if c.mode == "tcp":
            _require(is_loopback_host(c.host), "refusing non-loopback Tor ControlPort host")
            _require(1 <= c.port <= 65535, "control.port must be 1..65535")
        else:
            _require(os.path.isabs(c.socket_path), "control.socket_path must be absolute")
        _require(
            c.auth in {"auto", "safecookie", "hashedpassword", "null"},
            "control.auth must be one of 'auto', 'safecookie', 'hashedpassword', 'null'",
        )
        _require(
            not (c.password_env and c.password_file),
            "control.password_env and control.password_file are mutually exclusive",
        )
        if c.password_env is not None:
            _require(
                bool(_ENV_NAME_RE.fullmatch(c.password_env)),
                "control.password_env must be a valid environment variable name",
            )
        if c.password_file is not None:
            _require(
                os.path.isabs(c.password_file) or c.password_file.startswith(_CREDENTIALS_PREFIXES),
                "control.password_file must be absolute or start with ${CREDENTIALS_DIRECTORY}/",
            )
        has_password = bool(c.password_env or c.password_file)
        if c.auth == "hashedpassword":
            _require(has_password, "control.auth='hashedpassword' needs password_env or password_file")
        if c.auth in {"safecookie", "null"}:
            _require(not has_password, f"control.auth={c.auth!r} must not configure a password")
        if c.auth == "null":
            _require(c.allow_null_auth, "control.auth='null' also requires allow_null_auth = true")
        if c.cookie_path is not None:
            _require(os.path.isabs(c.cookie_path), "control.cookie_path must be absolute")
            _require(
                c.auth in {"auto", "safecookie"},
                "control.cookie_path is only meaningful for SAFECOOKIE authentication",
            )
        _require(
            0 < c.connect_timeout_seconds <= 60,
            "control.connect_timeout_seconds must be in (0, 60]",
        )
        _require(
            0 < c.signal_event_timeout_seconds <= 120,
            "control.signal_event_timeout_seconds must be in (0, 120]",
        )

    def _validate_socks(self) -> None:
        s = self.socks
        _require(s.mode in {"tcp", "unix"}, "socks.mode must be 'tcp' or 'unix'")
        if s.mode == "tcp":
            _require(bool(s.host.strip()), "socks.host must not be empty")
            _require(1 <= s.port <= 65535, "socks.port must be 1..65535")
            _require(
                s.allow_non_loopback or is_loopback_host(s.host),
                "refusing non-loopback SOCKS host (set socks.allow_non_loopback = true "
                "only for a trusted, private network path to Tor)",
            )
        else:
            _require(os.path.isabs(s.socket_path), "socks.socket_path must be absolute")
        for key in ("probe_username", "probe_password"):
            size = len(getattr(s, key).encode("utf-8"))
            _require(1 <= size <= 255, f"socks.{key} must be 1..255 bytes (RFC 1929)")

    def _validate_verify(self) -> None:
        v = self.verify
        custom_names: set[str] = set()
        for provider in v.custom_providers:
            _validate_custom_provider(provider)
            _require(
                provider.name not in custom_names,
                f"duplicate custom provider {provider.name!r}",
            )
            custom_names.add(provider.name)

        _require(len(v.providers) > 0, "verify.providers must not be empty")
        duplicates = sorted({p for p in v.providers if v.providers.count(p) > 1})
        # A provider listed twice would let one source satisfy a multi-source quorum.
        _require(not duplicates, f"verify.providers contains duplicates: {duplicates}")
        known = BUILTIN_PROVIDERS | custom_names
        unknown = sorted(set(v.providers) - known)
        _require(not unknown, f"unknown verification providers: {unknown}")

        _require(v.quorum >= 1, "verify.quorum must be >= 1")
        _require(
            v.quorum <= len(v.providers),
            "verify.quorum cannot exceed provider count",
        )
        if v.require_tor_confirmation:
            _require(
                bool(TOR_AUTHORITY_PROVIDERS & set(v.providers)),
                "verify.require_tor_confirmation needs a Tor-authoritative provider "
                f"({', '.join(sorted(TOR_AUTHORITY_PROVIDERS))}) in verify.providers",
            )
        _require(0 < v.timeout_seconds <= 120, "verify.timeout_seconds must be in (0, 120]")
        _require(
            1 <= v.attempts_after_rotation <= 20,
            "verify.attempts_after_rotation must be 1..20",
        )
        _require(1 <= v.max_rounds <= 10, "verify.max_rounds must be 1..10")
        _require(
            0 <= v.retry_delay_seconds <= 300,
            "verify.retry_delay_seconds must be in [0, 300]",
        )
        if v.ca_file is not None:
            _require(os.path.isabs(v.ca_file), "verify.ca_file must be absolute")

    def _validate_rotation(self) -> None:
        r = self.rotation
        _require(
            10 <= r.interval_seconds <= 7 * 24 * 3600,
            "rotation.interval_seconds must be in [10, 604800]",
        )
        _require(
            0 <= r.jitter_seconds < r.interval_seconds,
            "rotation.jitter_seconds must be >= 0 and < interval_seconds",
        )
        _require(0 <= r.settle_seconds <= 60, "rotation.settle_seconds must be in [0, 60]")
        _require(
            0 <= r.max_consecutive_failures <= 1_000_000,
            "rotation.max_consecutive_failures must be >= 0 (0 disables the limit)",
        )

    def _validate_runtime(self) -> None:
        rt = self.runtime
        _require(bool(rt.state_file.strip()), "runtime.state_file must not be empty")
        _require(bool(rt.lock_file.strip()), "runtime.lock_file must not be empty")
        paths = [rt.state_file, rt.lock_file] + ([rt.metrics_file] if rt.metrics_file else [])
        _require(
            len({os.path.normpath(p) for p in paths}) == len(paths),
            "runtime.state_file, lock_file and metrics_file must be distinct paths",
        )
        _require(
            rt.log_format in {"json", "text"},
            "runtime.log_format must be 'json' or 'text'",
        )
        _require(rt.log_level.upper() in _LOG_LEVELS, "unsupported runtime.log_level")

    # ------------------------------------------------------------------ secrets

    def control_password(self) -> str | None:
        """Resolve the control password from the environment or a credential file.

        The password is never stored in the configuration object itself.
        """
        c = self.control
        if c.password_env:
            value = os.environ.get(c.password_env)
            if not value:
                raise ConfigurationError(f"environment variable {c.password_env!r} is required but unset")
            return value
        if c.password_file:
            return _read_secret_file(_expand_credentials_path(c.password_file))
        return None

    # ----------------------------------------------------------------- display

    def to_redacted_dict(self) -> dict[str, Any]:
        """Effective configuration for display. Contains no secret material."""
        data = asdict(self)
        data["socks"]["probe_password"] = "<redacted>"  # noqa: S105 - display placeholder
        data["verify"]["providers"] = list(self.verify.providers)
        data["verify"]["custom_providers"] = [asdict(p) for p in self.verify.custom_providers]
        return data


# ---------------------------------------------------------------------- helpers


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and any loopback IPv4/IPv6 literal (``127.0.0.0/8``, ``::1``)."""
    candidate = host.strip()
    if candidate.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate.strip("[]")).is_loopback
    except ValueError:
        return False


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigurationError(message)


def _table(value: object, section: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"[{section}] must be a table")
    return value


def _build(cls: type[T], raw: dict[str, Any], section: str) -> T:
    hints = get_type_hints(cls)
    allowed = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ConfigurationError(f"unknown key(s) in [{section}]: {', '.join(unknown)}")
    kwargs = {name: _coerce(f"{section}.{name}", value, hints[name]) for name, value in raw.items()}
    return cls(**kwargs)


def _coerce(path: str, value: object, hint: Any) -> object:
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    if origin is Literal:
        if value not in args:
            choices = ", ".join(repr(a) for a in args)
            raise ConfigurationError(f"{path} must be one of {choices}")
        return value
    if origin in {types.UnionType, typing.Union}:
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return _coerce(path, value, non_none[0])
    if origin is tuple and args[-1] is Ellipsis:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigurationError(f"{path} must be a list of strings")
        return tuple(value)
    if hint is bool:
        if not isinstance(value, bool):
            raise ConfigurationError(f"{path} must be a boolean")
        return value
    if hint is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConfigurationError(f"{path} must be an integer")
        return value
    if hint is float:
        if not isinstance(value, int | float) or isinstance(value, bool):
            raise ConfigurationError(f"{path} must be a number")
        if not math.isfinite(value):
            raise ConfigurationError(f"{path} must be finite")
        return float(value)
    if hint is str:
        if not isinstance(value, str):
            raise ConfigurationError(f"{path} must be a string")
        return value
    raise ConfigurationError(f"{path} has an unsupported type")  # pragma: no cover


def _custom_providers(raw: object) -> tuple[CustomProvider, ...]:
    if not isinstance(raw, dict):
        raise ConfigurationError("[verify.custom_providers] must be a table of tables")
    providers: list[CustomProvider] = []
    for name, spec in raw.items():
        table = _table(spec, f"verify.custom_providers.{name}")
        if "name" in table:
            raise ConfigurationError(f"verify.custom_providers.{name}: the table name is the provider name")
        providers.append(
            _build(
                CustomProvider,
                {"name": name, **table},
                f"verify.custom_providers.{name}",
            )
        )
    return tuple(providers)


def _validate_custom_provider(provider: CustomProvider) -> None:
    prefix = f"verify.custom_providers.{provider.name}"
    _require(
        bool(_PROVIDER_NAME_RE.fullmatch(provider.name)),
        f"{prefix}: name must match {_PROVIDER_NAME_RE.pattern}",
    )
    _require(
        provider.name not in BUILTIN_PROVIDERS,
        f"{prefix}: name collides with a built-in provider",
    )
    parts = urlsplit(provider.url)
    _require(parts.scheme == "https", f"{prefix}: url must use https")
    _require(bool(parts.hostname), f"{prefix}: url must include a host")
    _require(
        parts.username is None and parts.password is None,
        f"{prefix}: url must not embed credentials",
    )
    _require(not parts.fragment, f"{prefix}: url must not contain a fragment")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ConfigurationError(f"{prefix}: url has an invalid port") from exc
    if provider.format == "json":
        _require(
            provider.json_field is not None and bool(_JSON_FIELD_RE.fullmatch(provider.json_field)),
            f"{prefix}: format='json' requires a simple json_field",
        )
    else:
        _require(provider.json_field is None, f"{prefix}: json_field requires format='json'")


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        raise ConfigurationError(f"cannot open config {path}: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError(f"config {path} is not a regular file")
        if info.st_mode & stat.S_IWOTH:
            raise ConfigurationError(f"refusing world-writable config file {path}")
        if info.st_size > MAX_CONFIG_BYTES:
            raise ConfigurationError(f"config {path} exceeds {MAX_CONFIG_BYTES} bytes")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot parse config {path}: {exc}") from exc


def _expand_credentials_path(path: str) -> str:
    for prefix in _CREDENTIALS_PREFIXES:
        if path.startswith(prefix):
            directory = os.environ.get("CREDENTIALS_DIRECTORY")
            if not directory:
                raise ConfigurationError(
                    "control.password_file references $CREDENTIALS_DIRECTORY, "
                    "which is unset (is the systemd LoadCredential= directive configured?)"
                )
            return os.path.join(directory, path[len(prefix) :])
    return path


def _read_secret_file(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ConfigurationError(f"cannot open control password file {path}: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError("control password file is not a regular file")
        if info.st_mode & stat.S_IRWXO:
            raise ConfigurationError(
                f"refusing control password file {path}: it is accessible to other users"
            )
        raw = os.read(fd, MAX_SECRET_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_SECRET_BYTES:
        raise ConfigurationError("control password file is too large")
    try:
        secret = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("control password file is not valid UTF-8") from exc
    secret = secret.removesuffix("\n").removesuffix("\r")
    if not secret:
        raise ConfigurationError("control password file is empty")
    return secret
