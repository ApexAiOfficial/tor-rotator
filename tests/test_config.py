from __future__ import annotations

import os
from dataclasses import replace

import pytest

from tor_rotator.config import (
    CONFIG_ENV_VAR,
    MAX_CONFIG_BYTES,
    AppConfig,
    ControlConfig,
    CustomProvider,
    SocksConfig,
    VerifyConfig,
    is_loopback_host,
)
from tor_rotator.errors import ConfigurationError


def write(tmp_path, text, mode=0o640, name="config.toml"):
    path = tmp_path / name
    path.write_text(text)
    path.chmod(mode)
    return path


def test_defaults_validate():
    AppConfig().validate()
    assert AppConfig().control.signal_event_timeout_seconds > 10  # outlasts Tor's NEWNYM rate limit


def test_load_without_path_uses_defaults(monkeypatch):
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    assert AppConfig.load() == AppConfig()


def test_load_from_env_var(tmp_path, monkeypatch):
    path = write(tmp_path, "[rotation]\ninterval_seconds = 42\n")
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))
    assert AppConfig.load().rotation.interval_seconds == 42.0


def test_load_full_file(tmp_path):
    path = write(
        tmp_path,
        """
[control]
mode = "unix"
socket_path = "/run/tor/control"
auth = "safecookie"
cookie_path = "/run/tor/control.authcookie"

[socks]
mode = "unix"
socket_path = "/run/tor/socks"

[verify]
quorum = 3
providers = ["torproject", "ipify", "icanhazip", "mine"]
require_unanimous = false

[verify.custom_providers.mine]
url = "https://echo.example.test/ip"

[rotation]
interval_seconds = 900
jitter_seconds = 120
max_consecutive_failures = 5

[runtime]
metrics_file = "/var/lib/node_exporter/textfile/tor_rotator.prom"
log_level = "debug"
""",
    )
    config = AppConfig.load(path)
    assert config.control.mode == "unix"
    assert config.verify.providers == ("torproject", "ipify", "icanhazip", "mine")
    assert config.verify.custom_providers == (CustomProvider("mine", "https://echo.example.test/ip"),)
    assert config.rotation.jitter_seconds == 120.0
    assert config.runtime.metrics_file is not None


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (lambda p: None, "cannot open"),
        (lambda p: p.mkdir(), "not a regular file"),
    ],
)
def test_load_file_errors(tmp_path, setup, message):
    path = tmp_path / "config.toml"
    setup(path)
    with pytest.raises(ConfigurationError, match=message):
        AppConfig.load(path)


def test_refuses_world_writable_config(tmp_path):
    path = write(tmp_path, "", mode=0o666)
    with pytest.raises(ConfigurationError, match="world-writable"):
        AppConfig.load(path)


def test_refuses_oversized_config(tmp_path):
    path = write(tmp_path, "#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigurationError, match="exceeds"):
        AppConfig.load(path)


@pytest.mark.parametrize("content", [b"[control\n", b"\xff\xfe"])
def test_refuses_unparseable_config(tmp_path, content):
    path = tmp_path / "config.toml"
    path.write_bytes(content)
    with pytest.raises(ConfigurationError, match="cannot parse"):
        AppConfig.load(path)


@pytest.mark.parametrize(
    ("mapping", "message"),
    [
        ({"bogus": {}}, "unknown config sections"),
        ({"control": []}, r"\[control\] must be a table"),
        ({"control": {"nope": 1}}, r"unknown key\(s\) in \[control\]: nope"),
        ({"control": {"password": "x"}}, "must not be stored"),
        ({"control": {"cookie": "x"}}, "must not be stored"),
        ({"control": {"port": "9051"}}, "control.port must be an integer"),
        ({"control": {"port": True}}, "control.port must be an integer"),
        ({"control": {"mode": "udp"}}, "control.mode must be one of"),
        ({"runtime": {"log_format": "xml"}}, "runtime.log_format must be one of"),
        ({"control": {"allow_null_auth": "yes"}}, "must be a boolean"),
        ({"control": {"connect_timeout_seconds": "5"}}, "must be a number"),
        ({"control": {"connect_timeout_seconds": float("nan")}}, "must be finite"),
        ({"control": {"connect_timeout_seconds": float("inf")}}, "must be finite"),
        ({"control": {"host": 127}}, "must be a string"),
        ({"control": {"password_env": 5}}, "must be a string"),
        ({"verify": {"providers": "torproject"}}, "list of strings"),
        ({"verify": {"providers": [1, 2]}}, "list of strings"),
        ({"verify": {"custom_providers": []}}, "table of tables"),
        ({"verify": {"custom_providers": {"x": 5}}}, "must be a table"),
        ({"verify": {"custom_providers": {"x": {"name": "y", "url": "https://a"}}}}, "table name"),
        ({"verify": {"custom_providers": {"x": {"url": "https://a", "bogus": 1}}}}, "unknown key"),
    ],
)
def test_type_checking(mapping, message):
    with pytest.raises(ConfigurationError, match=message):
        AppConfig.from_mapping(mapping)


def test_root_must_be_table():
    with pytest.raises(ConfigurationError, match="root"):
        AppConfig.from_mapping([])  # type: ignore[arg-type]


def test_integer_is_accepted_for_float_fields():
    config = AppConfig.from_mapping({"verify": {"timeout_seconds": 10}})
    assert isinstance(config.verify.timeout_seconds, float)


@pytest.mark.parametrize(
    ("mapping", "message"),
    [
        ({"control": {"host": "0.0.0.0"}}, "non-loopback Tor ControlPort"),
        ({"control": {"host": "tor.internal"}}, "non-loopback Tor ControlPort"),
        ({"control": {"port": 70000}}, "control.port"),
        ({"control": {"mode": "unix", "socket_path": "relative"}}, "socket_path must be absolute"),
        ({"control": {"password_env": "A", "password_file": "/x"}}, "mutually exclusive"),
        ({"control": {"password_env": "1BAD"}}, "valid environment variable"),
        ({"control": {"password_file": "relative"}}, "password_file must be absolute"),
        ({"control": {"auth": "hashedpassword"}}, "needs password_env"),
        ({"control": {"auth": "safecookie", "password_env": "X"}}, "must not configure a password"),
        ({"control": {"auth": "null"}}, "allow_null_auth"),
        ({"control": {"cookie_path": "relative"}}, "cookie_path must be absolute"),
        (
            {"control": {"cookie_path": "/c", "auth": "hashedpassword", "password_env": "X"}},
            "only meaningful for SAFECOOKIE",
        ),
        ({"control": {"connect_timeout_seconds": 0}}, "connect_timeout"),
        ({"control": {"signal_event_timeout_seconds": 500}}, "signal_event_timeout"),
        ({"socks": {"port": 0}}, "socks.port"),
        ({"socks": {"host": " "}}, "socks.host must not be empty"),
        ({"socks": {"host": "10.1.2.3"}}, "non-loopback SOCKS"),
        ({"socks": {"mode": "unix", "socket_path": "x"}}, "socks.socket_path must be absolute"),
        ({"socks": {"probe_username": ""}}, "probe_username"),
        ({"socks": {"probe_password": "x" * 256}}, "probe_password"),
        ({"verify": {"quorum": 0}}, "verify.quorum must be >= 1"),
        ({"verify": {"quorum": 4}}, "provider count"),
        ({"verify": {"providers": []}}, "must not be empty"),
        ({"verify": {"providers": ["ipify", "ipify"], "quorum": 2}}, "duplicates"),
        ({"verify": {"providers": ["nope", "torproject"]}}, "unknown verification providers"),
        ({"verify": {"providers": ["ipify", "icanhazip"]}}, "Tor-authoritative provider"),
        ({"verify": {"timeout_seconds": 0}}, "timeout_seconds"),
        ({"verify": {"attempts_after_rotation": 0}}, "attempts_after_rotation"),
        ({"verify": {"attempts_after_rotation": 21}}, "attempts_after_rotation"),
        ({"verify": {"retry_delay_seconds": -1}}, "retry_delay"),
        ({"verify": {"ca_file": "relative.pem"}}, "ca_file must be absolute"),
        ({"rotation": {"interval_seconds": 1}}, "interval_seconds"),
        ({"rotation": {"jitter_seconds": 600}}, "jitter_seconds"),
        ({"rotation": {"jitter_seconds": -1}}, "jitter_seconds"),
        ({"rotation": {"settle_seconds": 61}}, "settle_seconds"),
        ({"rotation": {"max_consecutive_failures": -1}}, "max_consecutive_failures"),
        ({"runtime": {"state_file": ""}}, "state_file must not be empty"),
        ({"runtime": {"lock_file": " "}}, "lock_file must not be empty"),
        ({"runtime": {"lock_file": "/var/lib/tor-rotator/state.json"}}, "distinct"),
        ({"runtime": {"log_level": "LOUD"}}, "log_level"),
    ],
)
def test_semantic_validation(mapping, message):
    config = AppConfig.from_mapping(mapping)
    with pytest.raises(ConfigurationError, match=message):
        config.validate()


def test_validation_of_mode_values_built_in_code():
    with pytest.raises(ConfigurationError, match="control.mode"):
        replace(AppConfig(), control=ControlConfig(mode="udp")).validate()  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="socks.mode"):
        replace(AppConfig(), socks=SocksConfig(mode="udp")).validate()  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="control.auth"):
        replace(AppConfig(), control=ControlConfig(auth="magic")).validate()  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="log_format"):
        replace(AppConfig(), runtime=replace(AppConfig().runtime, log_format="xml")).validate()  # type: ignore[arg-type]


def test_remote_socks_requires_explicit_opt_in():
    config = AppConfig.from_mapping({"socks": {"host": "tor", "allow_non_loopback": True}})
    config.validate()


def test_unix_modes_skip_tcp_checks():
    AppConfig.from_mapping(
        {"control": {"mode": "unix", "host": "0.0.0.0"}, "socks": {"mode": "unix", "host": "10.0.0.1"}}
    ).validate()


def test_tor_confirmation_can_be_disabled_for_ip_only_providers():
    AppConfig.from_mapping(
        {"verify": {"providers": ["ipify", "icanhazip"], "require_tor_confirmation": False}}
    ).validate()


@pytest.mark.parametrize(
    ("provider", "message"),
    [
        ({"url": "http://echo.example.test/"}, "must use https"),
        ({"url": "https:///path"}, "must include a host"),
        ({"url": "https://user:pw@echo.example.test/"}, "must not embed credentials"),
        ({"url": "https://echo.example.test/#frag"}, "fragment"),
        ({"url": "https://echo.example.test:99999/"}, "invalid port"),
        ({"url": "https://echo.example.test/", "format": "json"}, "requires a simple json_field"),
        ({"url": "https://echo.example.test/", "format": "json", "json_field": "a b"}, "simple json_field"),
        ({"url": "https://echo.example.test/", "json_field": "ip"}, "requires format='json'"),
    ],
)
def test_custom_provider_validation(provider, message):
    config = AppConfig.from_mapping(
        {"verify": {"providers": ["torproject", "mine"], "custom_providers": {"mine": provider}}}
    )
    with pytest.raises(ConfigurationError, match=message):
        config.validate()


@pytest.mark.parametrize(("name", "message"), [("Bad Name", "name must match"), ("ipify", "collides")])
def test_custom_provider_names(name, message):
    config = AppConfig.from_mapping(
        {
            "verify": {
                "providers": ["torproject"],
                "custom_providers": {name: {"url": "https://echo.example.test/"}},
            }
        }
    )
    with pytest.raises(ConfigurationError, match=message):
        config.validate()


def test_duplicate_custom_provider_objects_are_rejected():
    custom = CustomProvider("mine", "https://echo.example.test/")
    config = replace(
        AppConfig(),
        verify=VerifyConfig(providers=("torproject", "mine"), custom_providers=(custom, custom)),
    )
    with pytest.raises(ConfigurationError, match="duplicate custom provider"):
        config.validate()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", True),
        ("LOCALHOST", True),
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("10.0.0.1", False),
        ("example.org", False),
    ],
)
def test_is_loopback_host(host, expected):
    assert is_loopback_host(host) is expected


# --- secrets ------------------------------------------------------------------------


def test_password_env(monkeypatch):
    config = AppConfig.from_mapping({"control": {"password_env": "TR_TEST_SECRET"}})
    monkeypatch.setenv("TR_TEST_SECRET", "secret")
    assert config.control_password() == "secret"
    monkeypatch.delenv("TR_TEST_SECRET")
    with pytest.raises(ConfigurationError, match="required but unset"):
        config.control_password()


def test_no_password_configured():
    assert AppConfig().control_password() is None


def test_password_file(tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n")
    secret.chmod(0o600)
    config = AppConfig.from_mapping({"control": {"password_file": str(secret)}})
    assert config.control_password() == "hunter2"


def test_password_file_from_systemd_credentials(tmp_path, monkeypatch):
    (tmp_path / "tor-control").write_text("pw\r\n")
    (tmp_path / "tor-control").chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    for prefix in ("${CREDENTIALS_DIRECTORY}", "$CREDENTIALS_DIRECTORY"):
        config = AppConfig.from_mapping({"control": {"password_file": f"{prefix}/tor-control"}})
        config.validate()
        assert config.control_password() == "pw"
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(ConfigurationError, match="CREDENTIALS_DIRECTORY"):
        config.control_password()


@pytest.mark.parametrize(
    ("content", "mode", "message"),
    [
        (b"pw", 0o644, "accessible to other users"),
        (b"", 0o600, "empty"),
        (b"\xff", 0o600, "UTF-8"),
        (b"x" * 5000, 0o600, "too large"),
    ],
)
def test_password_file_rejections(tmp_path, content, mode, message):
    secret = tmp_path / "pw"
    secret.write_bytes(content)
    secret.chmod(mode)
    config = AppConfig.from_mapping({"control": {"password_file": str(secret)}})
    with pytest.raises(ConfigurationError, match=message):
        config.control_password()


def test_password_file_symlink_and_directory_are_refused(tmp_path):
    real = tmp_path / "real"
    real.write_text("pw")
    real.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    for path, message in ((link, "cannot open"), (tmp_path, "not a regular file")):
        config = AppConfig.from_mapping({"control": {"password_file": str(path)}})
        with pytest.raises(ConfigurationError, match=message):
            config.control_password()


def test_redacted_dict_hides_probe_password_and_contains_no_secret(monkeypatch):
    monkeypatch.setenv("TR_TEST_SECRET", "top-secret-value")
    config = AppConfig.from_mapping(
        {
            "control": {"password_env": "TR_TEST_SECRET"},
            "verify": {
                "providers": ["torproject", "mine"],
                "custom_providers": {"mine": {"url": "https://echo.example.test/"}},
            },
        }
    )
    data = config.to_redacted_dict()
    assert data["socks"]["probe_password"] == "<redacted>"
    assert data["control"]["password_env"] == "TR_TEST_SECRET"
    assert data["verify"]["custom_providers"][0]["name"] == "mine"
    assert "top-secret-value" not in repr(data)


def test_config_file_permissions_are_checked_on_the_opened_file(tmp_path):
    target = write(tmp_path, "", mode=0o666, name="real.toml")
    link = tmp_path / "config.toml"
    os.symlink(target, link)
    with pytest.raises(ConfigurationError, match="world-writable"):
        AppConfig.load(link)
