from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import trustme
from fakes import FakeHttps, FakeSocks, FakeTorControl

from tor_rotator.config import AppConfig, RotationConfig, RuntimeConfig, SocksConfig, VerifyConfig


@pytest.fixture
def short_tmp() -> Iterator[Path]:
    """A short temporary directory: AF_UNIX socket paths are limited to ~107 bytes."""
    path = Path(tempfile.mkdtemp(prefix="trt-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.WARNING)


@pytest.fixture(scope="session")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="session")
def ca_file(ca: trustme.CA, tmp_path_factory: pytest.TempPathFactory) -> str:
    path = tmp_path_factory.mktemp("ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return str(path)


@pytest.fixture(scope="session")
def https_server(ca: trustme.CA) -> Iterator[FakeHttps]:
    server = FakeHttps(ca)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def echo(https_server: FakeHttps) -> FakeHttps:
    """The shared HTTPS echo server, reset to unanimous, Tor-confirmed answers."""
    https_server.answer()
    https_server.requests.clear()
    return https_server


@pytest.fixture
def socks(short_tmp: Path, echo: FakeHttps) -> Iterator[FakeSocks]:
    with FakeSocks(short_tmp, upstream=echo.address) as server:
        yield server


@pytest.fixture
def control(short_tmp: Path) -> Iterator[FakeTorControl]:
    with FakeTorControl(short_tmp) as server:
        yield server


@dataclass
class Stack:
    """Fake Tor control port + SOCKS proxy + HTTPS echo, and a config wired to them."""

    control: FakeTorControl
    socks: FakeSocks
    echo: FakeHttps
    config: AppConfig


@pytest.fixture
def stack(control: FakeTorControl, socks: FakeSocks, echo: FakeHttps, ca_file: str, short_tmp: Path) -> Stack:
    config = AppConfig(
        control=control.control_config(),
        socks=socks.socks_config(),
        verify=VerifyConfig(
            ca_file=ca_file, timeout_seconds=5.0, attempts_after_rotation=2, retry_delay_seconds=0
        ),
        rotation=RotationConfig(interval_seconds=10, settle_seconds=0),
        runtime=RuntimeConfig(
            state_file=str(short_tmp / "state.json"),
            lock_file=str(short_tmp / "rotate.lock"),
            log_format="text",
        ),
    )
    return Stack(control=control, socks=socks, echo=echo, config=config)


def runtime_for(tmp_path: Path, **overrides: object) -> RuntimeConfig:
    values: dict[str, object] = {
        "state_file": str(tmp_path / "state.json"),
        "lock_file": str(tmp_path / "rotate.lock"),
        "log_format": "text",
    }
    values.update(overrides)
    return RuntimeConfig(**values)  # type: ignore[arg-type]


def offline_config(tmp_path: Path, **sections: object) -> AppConfig:
    """A valid config for tests that inject verifiers/controls (no sockets needed)."""
    values: dict[str, object] = {
        "socks": SocksConfig(),
        "verify": VerifyConfig(attempts_after_rotation=2, retry_delay_seconds=0),
        "rotation": RotationConfig(interval_seconds=10, settle_seconds=0),
        "runtime": runtime_for(tmp_path),
    }
    values.update(sections)
    return AppConfig(**values)  # type: ignore[arg-type]
