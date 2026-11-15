"""HTTPS GET through SOCKS5 with a hard total deadline and a bounded response size.

Built on the standard library only: no environment proxies, no ``.netrc``, no cookies,
no redirects, no local DNS. Certificates are verified against the system trust store
(or a configured CA file) with hostname checking and TLS 1.2 or newer.

A per-operation socket timeout alone cannot bound a request: a server that trickles one
byte just inside each timeout could hold a probe open almost indefinitely. A watchdog
therefore shuts the connection down when the total deadline passes, which unblocks
whatever read is in progress.
"""

from __future__ import annotations

import contextlib
import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from types import TracebackType
from typing import Final
from urllib.parse import urlsplit

from . import socks
from .errors import ProbeError, ProbeTimeoutError, ProxyError

MAX_BODY_BYTES: Final = 16 * 1024


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A complete, size-bounded HTTP response."""

    status: int
    reason: str
    body: bytes


def create_ssl_context(ca_file: str | None = None) -> ssl.SSLContext:
    """A verifying client context: system trust store (or *ca_file*), TLS >= 1.2."""
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _Deadline:
    """Shut a socket down once a deadline passes, unblocking any in-progress I/O."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._expires_at = time.monotonic() + seconds
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self.fired = False
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def __enter__(self) -> _Deadline:
        self._timer.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._timer.cancel()
        self.release()

    def remaining(self) -> float:
        remaining = self._expires_at - time.monotonic()
        if remaining <= 0:
            raise ProbeTimeoutError(f"probe exceeded its {self.seconds:g}s deadline")
        return remaining

    def guard(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
            if self.fired:
                _shutdown(sock)

    def release(self) -> None:
        """Stop guarding; must happen before the guarded socket is closed."""
        with self._lock:
            self._sock = None

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            if self._sock is not None:
                _shutdown(self._sock)


def _shutdown(sock: socket.socket) -> None:
    # Call the base-class method directly: ssl.SSLSocket.shutdown() would also discard the
    # TLS object underneath a concurrent read.
    with contextlib.suppress(OSError):
        socket.socket.shutdown(sock, socket.SHUT_RDWR)


def https_get(
    url: str,
    *,
    endpoint: socks.SocksEndpoint,
    ssl_context: ssl.SSLContext,
    timeout: float,
    user_agent: str,
    max_body: int = MAX_BODY_BYTES,
) -> HttpResponse:
    """Fetch *url* over HTTPS through the SOCKS5 *endpoint*.

    :raises ProbeTimeoutError: the total *timeout* elapsed.
    :raises ProbeError: TLS, HTTP, size-limit, or proxy failure.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ProbeError(f"refusing non-HTTPS probe URL {url!r}")
    host = parts.hostname
    port = parts.port or 443
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

    raw: socket.socket | None = None
    tls: ssl.SSLSocket | None = None
    conn: http.client.HTTPSConnection | None = None
    with _Deadline(timeout) as deadline:
        try:
            raw = socks.open_connection(
                endpoint, host, port, timeout=deadline.remaining(), on_connect=deadline.guard
            )
            raw.settimeout(deadline.remaining())
            deadline.release()  # wrap_socket() takes ownership of the descriptor
            tls = ssl_context.wrap_socket(raw, server_hostname=host)
            raw = None
            deadline.guard(tls)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_context)
            conn.sock = tls
            conn.request(
                "GET",
                target,
                headers={"User-Agent": user_agent, "Accept": "*/*", "Connection": "close"},
            )
            response = conn.getresponse()
            declared = response.getheader("Content-Length")
            if declared is not None and declared.strip().isdigit() and int(declared) > max_body:
                raise ProbeError(f"response declared {declared} bytes, over the {max_body}-byte limit")
            body = response.read(max_body + 1)
            if len(body) > max_body:
                raise ProbeError(f"response body exceeded the {max_body}-byte limit")
            return HttpResponse(status=response.status, reason=response.reason, body=body)
        except (ProbeError, ProxyError, OSError, http.client.HTTPException) as exc:
            if deadline.fired or isinstance(exc, TimeoutError):
                raise ProbeTimeoutError(f"probe exceeded its {timeout:g}s deadline") from exc
            if isinstance(exc, ProbeError | ProxyError):
                raise
            raise ProbeError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            deadline.release()
            if conn is not None:
                conn.close()
            if tls is not None:
                tls.close()
            if raw is not None:
                raw.close()
