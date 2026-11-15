"""In-process fakes: a Tor control port, a SOCKS5 proxy and HTTPS IP-echo servers.

They speak the real wire protocols over real sockets, so the production code paths
(socket I/O, timeouts, TLS verification, SOCKS negotiation) run unmodified in tests.
The SAFECOOKIE math here is an independent implementation of the spec, so it
cross-checks the production implementation rather than mirroring it.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import selectors
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import trustme

from tor_rotator.config import ControlConfig, SocksConfig

SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"

PROVIDER_HOSTS = (
    "check.torproject.org",
    "api.ipify.org",
    "ipv4.icanhazip.com",
    "checkip.amazonaws.com",
    "echo.example.test",
)

# Real, globally-routable addresses (Tor exit operator ranges); the documentation
# ranges (192.0.2.0/24 ...) are rejected by design because they are not global.
EXIT_A = "185.220.101.1"
EXIT_B = "185.220.101.2"
EXIT_C = "109.70.100.3"


def spec_hashes(cookie: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    material = cookie + client_nonce + server_nonce
    return (
        hmac.new(SERVER_KEY, material, hashlib.sha256).digest(),
        hmac.new(CLIENT_KEY, material, hashlib.sha256).digest(),
    )


def recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


class ThreadedServer:
    """Accept loop polling a listening socket; one handler thread per connection."""

    def __init__(self, listener: socket.socket) -> None:
        self._listener = listener
        listener.listen(16)
        listener.settimeout(0.05)
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._conns: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True)

    def __enter__(self) -> Any:
        self._acceptor.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(15)
            with self._lock:
                self._conns.add(conn)
            thread = threading.Thread(target=self._run, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _run(self, conn: socket.socket) -> None:
        try:
            self.handle(conn)
        except (OSError, ValueError, ConnectionError):
            pass
        finally:
            with self._lock:
                self._conns.discard(conn)
            conn.close()

    def handle(self, conn: socket.socket) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def stop(self) -> None:
        self._stopping.set()
        with self._lock:
            conns = list(self._conns)
        for conn in conns:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        self._acceptor.join(5)
        for thread in self._threads:
            thread.join(5)
        self._listener.close()


def _listener(directory: Path, unix: bool, name: str) -> tuple[socket.socket, str | None]:
    if unix:
        path = directory / name
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        return sock, str(path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    return sock, None


def tor_escape(path: str) -> str:
    """Escape like Tor's esc_for_log: backslash, quote, and C escapes for control bytes."""
    out = []
    for byte in os.fsencode(path):
        char = chr(byte)
        if char in '\\"':
            out.append("\\" + char)
        elif char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif char == "\r":
            out.append("\\r")
        elif byte < 0x20 or byte >= 0x7F:
            out.append(f"\\{byte:03o}")
        else:
            out.append(char)
    return "".join(out)


class FakeTorControl(ThreadedServer):
    """A scriptable Tor control port.

    ``newnym`` selects the SIGNAL NEWNYM behaviour:
    ``immediate`` (250 then 650), ``stale`` (650 *before* 250), ``ignored`` (250 only),
    ``delayed`` (650 after ``newnym_delay`` seconds), ``noise`` (unrelated events first),
    ``drop`` (close after 250), ``reject`` (552), ``spurious`` (an extra 250).
    """

    def __init__(
        self,
        directory: Path,
        *,
        unix: bool = False,
        methods: tuple[str, ...] = ("SAFECOOKIE",),
        password: str | None = None,
        newnym: str = "immediate",
        newnym_delay: float = 0.0,
        getinfo: dict[str, str] | None = None,
        bad_server_hash: bool = False,
        advertised_cookie: str | None = None,
        raw_script: bytes | None = None,
    ) -> None:
        sock, self.socket_path = _listener(directory, unix, "control.sock")
        super().__init__(sock)
        self.port = None if unix else sock.getsockname()[1]
        self.cookie = os.urandom(32)
        self.cookie_path = directory / "control.authcookie"
        self.cookie_path.write_bytes(self.cookie)
        self.methods = methods
        self.password = password
        self.newnym = newnym
        self.newnym_delay = newnym_delay
        self.bad_server_hash = bad_server_hash
        self.advertised_cookie = advertised_cookie or str(self.cookie_path)
        self.raw_script = raw_script
        self.commands: list[str] = []
        self.getinfo: dict[str, str] = {
            "version": "0.4.8.16",
            "status/bootstrap-phase": 'NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"',
            "status/circuit-established": "1",
            "network-liveness": "up",
            "net/listeners/socks": '"127.0.0.1:9050"',
            "circuit-status": "1 BUILT $A~a,$B~b,$C~c PURPOSE=GENERAL\n2 BUILT $D~d,$E~e,$F~f PURPOSE=GENERAL",
        }
        if getinfo is not None:
            self.getinfo.update(getinfo)

    def control_config(self, **overrides: Any) -> ControlConfig:
        base: dict[str, Any] = (
            {"mode": "unix", "socket_path": self.socket_path}
            if self.socket_path
            else {"mode": "tcp", "host": "127.0.0.1", "port": self.port}
        )
        base.update(connect_timeout_seconds=3.0, signal_event_timeout_seconds=1.0)
        base.update(overrides)
        return ControlConfig(**base)

    def handle(self, conn: socket.socket) -> None:
        if self.raw_script is not None:
            conn.sendall(self.raw_script)
            return
        with conn.makefile("rb") as reader:
            self._session(conn, reader)

    def _session(self, conn: socket.socket, reader: Any) -> None:  # noqa: PLR0912
        authenticated = False
        client_nonce: bytes | None = None
        server_nonce: bytes | None = None

        def send(text: str) -> None:
            conn.sendall(text.encode())

        while True:
            raw = reader.readline()
            if not raw:
                return
            line = raw.decode().rstrip("\r\n")
            self.commands.append(line)
            verb, _, arg = line.partition(" ")
            if verb == "PROTOCOLINFO":
                cookie = ""
                if {"SAFECOOKIE", "COOKIE"} & set(self.methods):
                    cookie = f' COOKIEFILE="{tor_escape(self.advertised_cookie)}"'
                send(
                    "250-PROTOCOLINFO 1\r\n"
                    f"250-AUTH METHODS={','.join(self.methods)}{cookie}\r\n"
                    '250-VERSION Tor="0.4.8.16"\r\n'
                    "250 OK\r\n"
                )
            elif verb == "AUTHCHALLENGE":
                _kind, _, nonce_hex = arg.partition(" ")
                client_nonce = bytes.fromhex(nonce_hex)
                server_nonce = os.urandom(32)
                server_hash, _ = spec_hashes(self.cookie, client_nonce, server_nonce)
                if self.bad_server_hash:
                    server_hash = bytes(32)
                send(
                    f"250 AUTHCHALLENGE SERVERHASH={server_hash.hex().upper()} "
                    f"SERVERNONCE={server_nonce.hex().upper()}\r\n"
                )
            elif verb == "AUTHENTICATE":
                ok = False
                if client_nonce is not None and server_nonce is not None:
                    _, client_hash = spec_hashes(self.cookie, client_nonce, server_nonce)
                    ok = arg.lower() == client_hash.hex()
                elif self.password is not None and arg:
                    ok = bytes.fromhex(arg) == self.password.encode()
                elif "NULL" in self.methods and not arg:
                    ok = True
                if not ok:
                    send("515 Authentication failed: Password did not match\r\n")
                    return
                authenticated = True
                send("250 OK\r\n")
            elif not authenticated:
                send("514 Authentication required.\r\n")
                return
            elif verb == "GETINFO":
                send(self._getinfo(arg.split()))
            elif verb == "SETEVENTS":
                send("250 OK\r\n")
            elif verb == "SIGNAL":
                if not self._signal(send, arg):
                    return
            elif verb == "QUIT":
                send("250 closing connection\r\n")
                return
            else:
                send(f'510 Unrecognized command "{verb}"\r\n')

    def _getinfo(self, keys: list[str]) -> str:
        unknown = [k for k in keys if k not in self.getinfo]
        if unknown:
            return f'552 Unrecognized key "{unknown[0]}"\r\n'
        parts = []
        for key in keys:
            value = self.getinfo[key]
            if "\n" in value or key == "circuit-status":
                body = "".join(("." + ln if ln.startswith(".") else ln) + "\r\n" for ln in value.splitlines())
                parts.append(f"250+{key}=\r\n{body}.\r\n")
            else:
                parts.append(f"250-{key}={value}\r\n")
        return "".join(parts) + "250 OK\r\n"

    def _signal(self, send: Callable[[str], None], arg: str) -> bool:
        mode = self.newnym
        if arg != "NEWNYM" or mode == "reject":
            send("552 Unrecognized signal code\r\n")
        elif mode == "immediate":
            send("250 OK\r\n650 SIGNAL NEWNYM\r\n")
        elif mode == "stale":
            send("650 SIGNAL NEWNYM\r\n250 OK\r\n")
        elif mode == "ignored":
            send("250 OK\r\n")
        elif mode == "delayed":
            send("250 OK\r\n")
            time.sleep(self.newnym_delay)
            send("650 SIGNAL NEWNYM\r\n")
        elif mode == "noise":
            send("250 OK\r\n650 SIGNAL RELOAD\r\n650-SIGNAL MULTI\r\n650 OK\r\n650 SIGNAL NEWNYM\r\n")
        elif mode == "drop":
            send("250 OK\r\n")
            return False
        elif mode == "spurious":
            send("250 OK\r\n250 OK\r\n")
        return True


class FakeSocks(ThreadedServer):
    """A SOCKS5 proxy that records requests and tunnels to an upstream address."""

    def __init__(
        self,
        directory: Path,
        *,
        unix: bool = False,
        upstream: tuple[str, int] | None = None,
        method: int = 0x02,
        version: int = 0x05,
        auth_status: int = 0,
        reply: int = 0,
        bound_atyp: int = 0x01,
        close_after_greeting: bool = False,
    ) -> None:
        sock, self.socket_path = _listener(directory, unix, "socks.sock")
        super().__init__(sock)
        self.port = None if unix else sock.getsockname()[1]
        self.upstream = upstream
        self.method = method
        self.version = version
        self.auth_status = auth_status
        self.reply = reply
        self.bound_atyp = bound_atyp
        self.close_after_greeting = close_after_greeting
        self.requests: list[dict[str, Any]] = []

    def socks_config(self, **overrides: Any) -> SocksConfig:
        base: dict[str, Any] = (
            {"mode": "unix", "socket_path": self.socket_path}
            if self.socket_path
            else {"mode": "tcp", "host": "127.0.0.1", "port": self.port}
        )
        base.update(overrides)
        return SocksConfig(**base)

    def handle(self, conn: socket.socket) -> None:
        _version, count = recv_exact(conn, 2)
        recv_exact(conn, count)
        if self.close_after_greeting:
            return
        conn.sendall(bytes([self.version, self.method]))
        if self.method != 0x02:
            return
        recv_exact(conn, 1)
        username = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
        password = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
        conn.sendall(bytes([1, self.auth_status]))
        if self.auth_status:
            return
        _ver, _cmd, _rsv, atyp = recv_exact(conn, 4)
        if atyp == 0x03:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode()
        elif atyp == 0x01:
            host = socket.inet_ntop(socket.AF_INET, recv_exact(conn, 4))
        else:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
        port = int.from_bytes(recv_exact(conn, 2), "big")
        self.requests.append(
            {"username": username, "password": password, "atyp": atyp, "host": host, "port": port}
        )
        bound = {
            0x01: b"\x01" + bytes(4),
            0x04: b"\x04" + bytes(16),
            0x03: b"\x03\x09localhost",
            0x09: b"\x09",
        }[self.bound_atyp]
        if self.reply or self.upstream is None:
            conn.sendall(bytes([5, self.reply or 0x01, 0]) + bound + b"\x00\x00")
            return
        with socket.create_connection(self.upstream, timeout=15) as upstream:
            conn.sendall(bytes([5, 0, 0]) + bound + b"\x00\x00")
            _pipe(conn, upstream)


def _pipe(a: socket.socket, b: socket.socket) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(a, selectors.EVENT_READ, b)
        selector.register(b, selectors.EVENT_READ, a)
        while True:
            events = selector.select(timeout=15)
            if not events:
                return
            for key, _ in events:
                source: socket.socket = key.fileobj  # type: ignore[assignment]
                data = source.recv(65536)
                if not data:
                    return
                key.data.sendall(data)


@dataclass
class EchoResponse:
    """What an echo host answers."""

    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    drip_delay: float = 0.0
    chunked: bool = False


class FakeHttps:
    """A TLS IP-echo server for every provider hostname, routed by the Host header."""

    def __init__(self, ca: trustme.CA) -> None:
        cert = ca.issue_cert(*PROVIDER_HOSTS)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert.configure_cert(context)
        self.responses: dict[str, EchoResponse] = {}
        self.requests: list[dict[str, str]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                host = (self.headers.get("Host") or "").split(":")[0]
                server.requests.append(
                    {"host": host, "path": self.path, "user_agent": self.headers.get("User-Agent", "")}
                )
                response = server.responses.get(host, EchoResponse(b"not found", status=404))
                self.send_response(response.status)
                for name, value in response.headers.items():
                    self.send_header(name, value)
                if response.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                elif "Content-Length" not in response.headers:
                    self.send_header("Content-Length", str(len(response.body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if response.chunked:
                    for start in range(0, len(response.body), 1024):
                        piece = response.body[start : start + 1024]
                        self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                    self.wfile.write(b"0\r\n\r\n")
                elif response.drip_delay:
                    for byte in response.body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(response.drip_delay)
                else:
                    self.wfile.write(response.body)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

            def handle_error(self, request: Any, client_address: Any) -> None:
                return

        self._httpd = Server(("127.0.0.1", 0), Handler)
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self.address: tuple[str, int] = self._httpd.server_address[:2]  # type: ignore[assignment]
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05})
        self._thread.daemon = True
        self._thread.start()

    def answer(
        self,
        torproject: tuple[str, bool] | None = (EXIT_A, True),
        ipify: str | None = EXIT_A,
        icanhazip: str | None = EXIT_A,
        aws: str | None = EXIT_A,
    ) -> None:
        """Configure the echo answers for the built-in providers."""
        self.responses.clear()
        if torproject is not None:
            ip, is_tor = torproject
            body = f'{{"IsTor":{str(is_tor).lower()},"IP":"{ip}"}}'.encode()
            self.responses["check.torproject.org"] = EchoResponse(body)
        if ipify is not None:
            self.responses["api.ipify.org"] = EchoResponse(f'{{"ip":"{ipify}"}}'.encode())
        if icanhazip is not None:
            self.responses["ipv4.icanhazip.com"] = EchoResponse(f"{icanhazip}\n".encode())
        if aws is not None:
            self.responses["checkip.amazonaws.com"] = EchoResponse(f"{aws}\n".encode())

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(5)
