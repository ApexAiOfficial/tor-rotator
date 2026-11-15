"""Socket connection helpers with loopback enforcement."""

from __future__ import annotations

import ipaddress
import socket


def is_loopback_address(address: str) -> bool:
    """True when *address* (an IP literal, possibly with a scope id) is loopback."""
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def connect_tcp(
    host: str,
    port: int,
    *,
    timeout: float,
    require_loopback: bool,
    error: type[Exception],
    purpose: str,
) -> socket.socket:
    """Connect to *host*:*port*, optionally refusing any non-loopback resolution.

    Loopback enforcement happens on the *resolved* addresses, so a hostname such as
    ``localhost`` that an attacker re-points in ``/etc/hosts`` cannot redirect the
    connection off-host.
    """
    try:
        candidates = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise error(f"cannot resolve {purpose} host {host!r}: {exc}") from exc
    failures: list[str] = []
    for family, sock_type, proto, _canonical, sockaddr in candidates:
        address = str(sockaddr[0])
        if require_loopback and not is_loopback_address(address):
            failures.append(f"{address}: refused (not loopback)")
            continue
        sock = socket.socket(family, sock_type, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
        except OSError as exc:
            sock.close()
            failures.append(f"{address}: {exc}")
            continue
        return sock
    detail = "; ".join(failures) or "no addresses"
    raise error(f"cannot connect to {purpose} at {host}:{port} ({detail})")


def connect_unix(path: str, *, timeout: float, error: type[Exception], purpose: str) -> socket.socket:
    """Connect to a UNIX-domain stream socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(path)
    except OSError as exc:
        sock.close()
        raise error(f"cannot connect to {purpose} socket {path}: {exc}") from exc
    return sock
