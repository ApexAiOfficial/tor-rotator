"""SOCKS5 client (RFC 1928) with username/password authentication (RFC 1929).

Destination hostnames are always sent to the proxy as domain names (``ATYP=0x03``), so
name resolution happens inside Tor and never in this process. This is the guarantee
``socks5h://`` provides in other clients, enforced here by construction.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Final

from ._net import connect_tcp, connect_unix
from .config import SocksConfig
from .errors import ProxyError

_VERSION: Final = 0x05
_AUTH_USERPASS: Final = 0x02
_AUTH_REJECTED: Final = 0xFF
_CMD_CONNECT: Final = 0x01
_ATYP_IPV4: Final = 0x01
_ATYP_DOMAIN: Final = 0x03
_ATYP_IPV6: Final = 0x04

REPLY_MESSAGES: Final = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
    # Tor extended error codes (SocksPort ExtendedErrors flag).
    0xF0: "onion service descriptor not found",
    0xF1: "onion service descriptor invalid",
    0xF2: "onion service introduction failed",
    0xF3: "onion service rendezvous failed",
    0xF4: "onion service missing client authorization",
    0xF5: "onion service wrong client authorization",
    0xF6: "invalid onion service address",
    0xF7: "onion service introduction timed out",
}


@dataclass(frozen=True, slots=True)
class SocksEndpoint:
    """Where the SOCKS5 proxy listens and which isolation credentials to present."""

    mode: str
    host: str
    port: int
    socket_path: str
    username: str
    password: str
    require_loopback: bool = True

    @classmethod
    def from_config(cls, config: SocksConfig) -> SocksEndpoint:
        return cls(
            mode=config.mode,
            host=config.host,
            port=config.port,
            socket_path=config.socket_path,
            username=config.probe_username,
            password=config.probe_password,
            require_loopback=not config.allow_non_loopback,
        )

    def describe(self) -> str:
        return f"unix:{self.socket_path}" if self.mode == "unix" else f"{self.host}:{self.port}"


def open_connection(
    endpoint: SocksEndpoint,
    dest_host: str,
    dest_port: int,
    *,
    timeout: float,
) -> socket.socket:
    """Return a socket tunnelled through the proxy to *dest_host*:*dest_port*."""
    if endpoint.mode == "unix":
        sock = connect_unix(endpoint.socket_path, timeout=timeout, error=ProxyError, purpose="SOCKS")
    else:
        sock = connect_tcp(
            endpoint.host,
            endpoint.port,
            timeout=timeout,
            require_loopback=endpoint.require_loopback,
            error=ProxyError,
            purpose="SOCKS proxy",
        )
    try:
        _handshake(sock, endpoint, dest_host, dest_port)
    except BaseException:
        sock.close()
        raise
    return sock


def encode_address(host: str) -> bytes:
    """Encode a SOCKS5 destination address (``ATYP`` + address)."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None:
        atyp = _ATYP_IPV4 if address.version == 4 else _ATYP_IPV6
        return bytes([atyp]) + address.packed
    try:
        encoded = host.encode("idna")
    except UnicodeError as exc:
        raise ProxyError(f"destination hostname {host!r} cannot be IDNA-encoded") from exc
    if not 1 <= len(encoded) <= 255:
        raise ProxyError("destination hostname must be 1..255 bytes")
    return bytes([_ATYP_DOMAIN, len(encoded)]) + encoded


def _handshake(sock: socket.socket, endpoint: SocksEndpoint, dest_host: str, dest_port: int) -> None:
    if not 1 <= dest_port <= 65535:
        raise ProxyError("destination port must be 1..65535")
    username = endpoint.username.encode("utf-8")
    password = endpoint.password.encode("utf-8")
    if not (1 <= len(username) <= 255 and 1 <= len(password) <= 255):
        raise ProxyError("SOCKS credentials must be 1..255 bytes each")
    try:
        # Offer only username/password: Tor accepts any pair and uses it as an
        # isolation key, which is what keeps probe traffic off application circuits.
        sock.sendall(bytes([_VERSION, 1, _AUTH_USERPASS]))
        version, method = _recv_exact(sock, 2)
        if version != _VERSION:
            raise ProxyError("proxy did not answer as a SOCKS5 server")
        if method == _AUTH_REJECTED:
            raise ProxyError("SOCKS proxy rejected username/password authentication")
        if method != _AUTH_USERPASS:
            raise ProxyError(f"SOCKS proxy selected unoffered authentication method 0x{method:02x}")

        sock.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
        auth_version, auth_status = _recv_exact(sock, 2)
        if auth_version != 1 or auth_status != 0:
            raise ProxyError("SOCKS username/password authentication failed")

        request = bytes([_VERSION, _CMD_CONNECT, 0x00]) + encode_address(dest_host)
        sock.sendall(request + dest_port.to_bytes(2, "big"))
        version, reply, _reserved, atyp = _recv_exact(sock, 4)
        if version != _VERSION:
            raise ProxyError("malformed SOCKS5 CONNECT reply")
        if reply != 0:
            message = REPLY_MESSAGES.get(reply, "unknown SOCKS error")
            raise ProxyError(f"SOCKS CONNECT to {dest_host}:{dest_port} failed: {message} (0x{reply:02x})")
        if atyp == _ATYP_IPV4:
            _recv_exact(sock, 4 + 2)
        elif atyp == _ATYP_IPV6:
            _recv_exact(sock, 16 + 2)
        elif atyp == _ATYP_DOMAIN:
            (length,) = _recv_exact(sock, 1)
            _recv_exact(sock, length + 2)
        else:
            raise ProxyError(f"SOCKS5 reply used unknown address type 0x{atyp:02x}")
    except TimeoutError as exc:
        raise ProxyError("timed out during SOCKS5 negotiation") from exc
    except OSError as exc:
        raise ProxyError(f"SOCKS5 negotiation failed: {exc}") from exc


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ProxyError("SOCKS proxy closed the connection during negotiation")
        buffer += chunk
    return bytes(buffer)
