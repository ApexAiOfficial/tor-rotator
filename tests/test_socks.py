from __future__ import annotations

import socket
import threading

import pytest
from fakes import FakeSocks

from tor_rotator.config import SocksConfig
from tor_rotator.errors import ProxyError
from tor_rotator.socks import SocksEndpoint, encode_address, open_connection


def endpoint(fake: FakeSocks, **overrides: object) -> SocksEndpoint:
    return SocksEndpoint.from_config(fake.socks_config(**overrides))


def test_encode_address():
    assert encode_address("check.torproject.org") == b"\x03\x14check.torproject.org"
    assert encode_address("185.220.101.1") == b"\x01" + bytes([185, 220, 101, 1])
    assert encode_address("[2001:db8::1]")[0] == 0x04
    assert encode_address("bücher.example")[2:].startswith(b"xn--")
    with pytest.raises(ProxyError, match="1..255"):
        encode_address(".".join(["a" * 50] * 6))
    with pytest.raises(ProxyError, match="IDNA"):
        encode_address("bad..label")


def test_endpoint_from_config_and_describe():
    tcp = SocksEndpoint.from_config(SocksConfig())
    assert tcp.describe() == "127.0.0.1:9050"
    assert tcp.require_loopback
    unix = SocksEndpoint.from_config(SocksConfig(mode="unix", allow_non_loopback=True))
    assert unix.describe() == "unix:/run/tor/socks"
    assert not unix.require_loopback


@pytest.mark.parametrize("unix", [False, True])
def test_negotiation_sends_domain_name_never_resolving_locally(short_tmp, unix):
    with FakeSocks(short_tmp, unix=unix, reply=0x04) as fake:
        with pytest.raises(ProxyError, match="host unreachable"):
            open_connection(endpoint(fake), "check.torproject.org", 443, timeout=3)
    assert fake.requests[0]["atyp"] == 0x03
    assert fake.requests[0]["host"] == "check.torproject.org"
    assert fake.requests[0]["port"] == 443


@pytest.mark.parametrize("bound_atyp", [0x01, 0x03, 0x04])
def test_tunnel_carries_bytes(short_tmp, bound_atyp):
    upstream = socket.socket()
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    with upstream, FakeSocks(short_tmp, upstream=upstream.getsockname(), bound_atyp=bound_atyp) as fake:
        with open_connection(endpoint(fake), "example.onion", 80, timeout=3) as tunnel:
            server_side, _ = upstream.accept()
            with server_side:
                tunnel.sendall(b"ping")
                assert server_side.recv(4) == b"ping"
                server_side.sendall(b"pong")
                assert tunnel.recv(4) == b"pong"
    assert fake.requests[0]["username"] == "tor-rotator-probe"


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"method": 0xFF}, "rejected username/password"),
        ({"method": 0x00}, "unoffered authentication method 0x00"),
        ({"version": 0x04}, "did not answer as a SOCKS5 server"),
        ({"auth_status": 1}, "authentication failed"),
        ({"reply": 0x05}, "connection refused"),
        ({"reply": 0xF6}, "invalid onion service address"),
        ({"reply": 0x42}, "unknown SOCKS error"),
        ({"close_after_greeting": True}, "closed the connection"),
    ],
)
def test_negotiation_failures(short_tmp, options, message):
    with FakeSocks(short_tmp, **options) as fake:
        with pytest.raises(ProxyError, match=message):
            open_connection(endpoint(fake), "check.torproject.org", 443, timeout=3)


def test_unknown_bound_address_type(short_tmp):
    peer_server = socket.socket()
    peer_server.bind(("127.0.0.1", 0))
    peer_server.listen(1)
    port = peer_server.getsockname()[1]

    def serve() -> None:
        conn, _ = peer_server.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05\x02")
            conn.recv(64)
            conn.sendall(b"\x01\x00")
            conn.recv(64)
            conn.sendall(b"\x05\x00\x00\x09")

    thread = threading.Thread(target=serve)
    thread.start()
    with peer_server:
        with pytest.raises(ProxyError, match="unknown address type"):
            open_connection(
                SocksEndpoint("tcp", "127.0.0.1", port, "", "u", "p"), "example.org", 443, timeout=3
            )
        thread.join(5)


def test_bad_destination_port_and_credentials():
    with pytest.raises(ProxyError, match="port"):
        _handshake_only(dest_port=0)
    with pytest.raises(ProxyError, match="credentials"):
        _handshake_only(username="")


def _handshake_only(dest_port: int = 443, username: str = "u") -> None:
    from tor_rotator.socks import _handshake

    a, b = socket.socketpair()
    with a, b:
        _handshake(a, SocksEndpoint("tcp", "h", 1, "", username, "p"), "example.org", dest_port)


def test_timeout_during_negotiation(short_tmp):
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(1)
    with silent, pytest.raises(ProxyError, match="timed out"):
        open_connection(
            SocksEndpoint("tcp", "127.0.0.1", silent.getsockname()[1], "", "u", "p"),
            "example.org",
            443,
            timeout=0.3,
        )


def test_reset_during_negotiation():
    a, b = socket.socketpair()
    b.close()
    from tor_rotator.socks import _handshake

    with a, pytest.raises(ProxyError, match="negotiation failed"):
        _handshake(a, SocksEndpoint("tcp", "h", 1, "", "u", "p"), "example.org", 443)


def test_non_loopback_socks_is_refused_at_connect(monkeypatch):
    def resolve_elsewhere(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.9", port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve_elsewhere)
    with pytest.raises(ProxyError, match="not loopback"):
        open_connection(
            SocksEndpoint.from_config(SocksConfig(host="localhost")), "example.org", 443, timeout=1
        )


def test_missing_unix_socket(short_tmp):
    config = SocksConfig(mode="unix", socket_path=str(short_tmp / "absent"))
    with pytest.raises(ProxyError, match="cannot connect"):
        open_connection(SocksEndpoint.from_config(config), "example.org", 443, timeout=1)
