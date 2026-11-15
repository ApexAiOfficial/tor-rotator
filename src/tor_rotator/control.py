"""Minimal, hardened Tor Control Protocol client.

Only the protocol surface this project needs is implemented: ``PROTOCOLINFO``,
``AUTHCHALLENGE``/``AUTHENTICATE`` (SAFECOOKIE, HASHEDPASSWORD, and opt-in NULL),
``GETINFO``, ``SETEVENTS`` and ``SIGNAL NEWNYM``. A purpose-built client keeps the
dependency surface at zero and lets every parsing rule fail closed.

Reference: Tor control-spec (https://spec.torproject.org/control-spec/).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import socket
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Final, Protocol, Self

from ._net import connect_tcp, connect_unix
from .config import ControlConfig
from .errors import ControlCommandError, ControlError, ControlTimeoutError
from .models import ControlStatus, NewnymOutcome

_SERVER_HASH_KEY: Final = b"Tor safe cookie authentication server-to-controller hash"
_CLIENT_HASH_KEY: Final = b"Tor safe cookie authentication controller-to-server hash"
_AUTH_RE: Final = re.compile(
    r'^AUTH METHODS=(?P<methods>[A-Za-z0-9,]+)(?: COOKIEFILE=(?P<cookie>"(?:[^"\\]|\\.)*"))?(?: .*)?$'
)
_CHALLENGE_RE: Final = re.compile(
    r"^AUTHCHALLENGE SERVERHASH=(?P<hash>[0-9A-Fa-f]{64}) SERVERNONCE=(?P<nonce>[0-9A-Fa-f]{64})$"
)
_QUOTED_RE: Final = re.compile(r'"(?:[^"\\]|\\.)*"')
_PROGRESS_RE: Final = re.compile(r"\bPROGRESS=(\d{1,3})\b")
_GETINFO_KEY_RE: Final = re.compile(r"^[A-Za-z0-9/_.:-]+$")

MAX_LINE_BYTES: Final = 64 * 1024
MAX_REPLY_BYTES: Final = 16 * 1024 * 1024
COOKIE_LEN: Final = 32

_STATUS_KEYS: Final = (
    "version",
    "status/bootstrap-phase",
    "status/circuit-established",
    "network-liveness",
    "net/listeners/socks",
    "circuit-status",
)
_STATUS_KEYS_MINIMAL: Final = ("version", "status/bootstrap-phase", "circuit-status")
_SIMPLE_ESCAPES: Final = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'"}


class ControlBackend(Protocol):
    """What :class:`~tor_rotator.service.TorRotatorService` needs from a control client."""

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    def status(self) -> ControlStatus: ...

    def signal_newnym(self) -> NewnymOutcome: ...


@dataclass(frozen=True, slots=True)
class ReplyLine:
    """One reply line; ``data`` holds the dot-decoded block of a ``+`` line."""

    status: int
    separator: str
    text: str
    data: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class Reply:
    """A complete synchronous reply, or one asynchronous event."""

    code: int
    lines: tuple[ReplyLine, ...]

    @property
    def texts(self) -> tuple[str, ...]:
        return tuple(line.text for line in self.lines)


def unquote(token: str) -> str:
    """Decode a control-protocol ``QuotedString``.

    Tor escapes ``\\``, ``"``, and control/non-printable bytes as C escapes (``\\n``,
    ``\\t``, ``\\r`` and up-to-three-digit octal). Any other ``\\X`` is the literal ``X``,
    per the quoted-pair grammar. The decoded bytes are mapped to ``str`` with the
    filesystem encoding so that paths round-trip exactly.
    """
    if len(token) < 2 or not (token.startswith('"') and token.endswith('"')):
        raise ControlError("expected a quoted string in Tor control reply")
    body = token[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char == '"':
            raise ControlError("unescaped quote inside Tor quoted string")
        if char != "\\":
            out += char.encode("utf-8")
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise ControlError("dangling escape in Tor quoted string")
        escape = body[index]
        if escape in "01234567":
            end = index
            while end < len(body) and end - index < 3 and body[end] in "01234567":
                end += 1
            value = int(body[index:end], 8)
            if value > 0xFF:
                raise ControlError("octal escape out of range in Tor quoted string")
            out.append(value)
            index = end
            continue
        out += _SIMPLE_ESCAPES.get(escape, escape).encode("utf-8")
        index += 1
    return os.fsdecode(bytes(out))


def safe_cookie_hashes(cookie: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    """Return ``(server_hash, client_hash)`` for SAFECOOKIE authentication."""
    material = cookie + client_nonce + server_nonce
    server_hash = hmac.new(_SERVER_HASH_KEY, material, hashlib.sha256).digest()
    client_hash = hmac.new(_CLIENT_HASH_KEY, material, hashlib.sha256).digest()
    return server_hash, client_hash


def read_cookie(path: str) -> bytes:
    """Read a SAFECOOKIE file without following symlinks; it must hold exactly 32 bytes."""
    if not os.path.isabs(path):
        raise ControlError("Tor authentication cookie path must be absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ControlError(f"cannot open Tor SAFECOOKIE file {path}: {exc.strerror or exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ControlError("Tor SAFECOOKIE path is not a regular file")
        cookie = os.read(fd, COOKIE_LEN + 1)
    finally:
        os.close(fd)
    if len(cookie) != COOKIE_LEN:
        raise ControlError("Tor SAFECOOKIE file must contain exactly 32 bytes")
    return cookie


class TorControlClient:
    """A single authenticated control connection, used as a context manager.

    >>> with TorControlClient(config.control, password) as tor:  # doctest: +SKIP
    ...     outcome = tor.signal_newnym()
    """

    def __init__(
        self,
        config: ControlConfig,
        password: str | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._password = password
        self._clock = clock
        self._socket: socket.socket | None = None
        self._buffer = bytearray()
        self._deadline = 0.0
        self._events: list[tuple[ReplyLine, ...]] = []
        self._reply_bytes = 0
        self._broken = False

    # -------------------------------------------------------------- lifecycle

    def __enter__(self) -> Self:
        try:
            self._connect()
            self._authenticate(self._command("PROTOCOLINFO 1"))
        except ControlError:
            self.close()
            raise
        except OSError as exc:
            self.close()
            raise ControlError(f"Tor control connection failed: {exc}") from exc
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection. Idempotent."""
        sock, self._socket = self._socket, None
        self._buffer.clear()
        if sock is not None:
            sock.close()

    def _connect(self) -> None:
        cfg = self.config
        timeout = cfg.connect_timeout_seconds
        if cfg.mode == "unix":
            sock = connect_unix(cfg.socket_path, timeout=timeout, error=ControlError, purpose="Tor control")
        else:
            sock = connect_tcp(
                cfg.host,
                cfg.port,
                timeout=timeout,
                require_loopback=True,
                error=ControlError,
                purpose="Tor ControlPort",
            )
        self._attach(sock)

    def _attach(self, sock: socket.socket) -> None:
        self._socket = sock
        self._buffer.clear()
        self._broken = False

    # --------------------------------------------------------------- wire I/O

    def _send(self, command: str) -> None:
        if self._socket is None or self._broken:
            raise ControlError("Tor control connection is not usable")
        if "\r" in command or "\n" in command:
            raise ControlError("control commands must be single-line")
        try:
            self._socket.sendall(command.encode("ascii") + b"\r\n")
        except (OSError, UnicodeEncodeError) as exc:
            self._broken = True
            raise ControlError(f"unable to send Tor control command: {exc}") from exc

    def _fail(self, error: ControlError) -> ControlError:
        self._broken = True
        return error

    def _readline(self) -> str:
        """Read one line before ``self._deadline``.

        Each ``recv`` is limited to the time left until the reply's deadline, so a peer that
        trickles bytes cannot stretch a reply beyond it (a per-``recv`` timeout alone could
        be stretched almost indefinitely, one byte per timeout).
        """
        sock = self._socket
        if sock is None or self._broken:
            raise ControlError("Tor control connection is not usable")
        while (newline := self._buffer.find(b"\n")) < 0:
            if len(self._buffer) > MAX_LINE_BYTES:
                raise self._fail(ControlError("Tor control reply line exceeded safety limit"))
            remaining = self._deadline - self._clock()
            if remaining <= 0:
                raise self._fail(ControlTimeoutError("timed out waiting for Tor control reply"))
            try:
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
            except TimeoutError as exc:
                raise self._fail(ControlTimeoutError("timed out waiting for Tor control reply")) from exc
            except OSError as exc:
                raise self._fail(ControlError(f"unable to read Tor control reply: {exc}")) from exc
            if not chunk:
                message = "closed mid-line" if self._buffer else "closed unexpectedly"
                raise self._fail(ControlError(f"Tor control connection {message}"))
            self._buffer += chunk
        raw = bytes(self._buffer[: newline + 1])
        del self._buffer[: newline + 1]
        if len(raw) > MAX_LINE_BYTES:
            raise self._fail(ControlError("Tor control reply line exceeded safety limit"))
        self._reply_bytes += len(raw)
        if self._reply_bytes > MAX_REPLY_BYTES:
            self._broken = True
            raise ControlError("Tor control reply exceeded safety limit")
        try:
            return raw.rstrip(b"\r\n").decode("utf-8")
        except UnicodeDecodeError as exc:
            self._broken = True
            raise ControlError("Tor control reply was not valid UTF-8") from exc

    def _read_data_block(self) -> tuple[str, ...]:
        lines: list[str] = []
        while True:
            line = self._readline()
            if line == ".":
                return tuple(lines)
            # Dot-stuffing: a data line beginning with "." is sent with an extra leading ".".
            lines.append(line[1:] if line.startswith("..") else line)

    def _read_reply(self, *, stop_on_event: bool = False, deadline: float | None = None) -> Reply:
        """Read one synchronous reply, queueing any asynchronous events that precede it.

        With *stop_on_event*, the first complete asynchronous event is returned instead.
        The whole reply must arrive before *deadline* (default: ``connect_timeout_seconds``
        from now).
        """
        self._deadline = (
            deadline if deadline is not None else self._clock() + self.config.connect_timeout_seconds
        )
        self._reply_bytes = 0
        code: int | None = None
        lines: list[ReplyLine] = []
        event: list[ReplyLine] = []
        while True:
            raw = self._readline()
            if len(raw) < 4 or not raw[:3].isdigit() or raw[3] not in " -+":
                self._broken = True
                raise ControlError(f"malformed Tor control reply: {raw[:120]!r}")
            status, separator, text = int(raw[:3]), raw[3], raw[4:]
            data = self._read_data_block() if separator == "+" else None
            line = ReplyLine(status, separator, text, data)

            if status == 650:
                event.append(line)
                if separator != " ":
                    continue
                completed, event = tuple(event), []
                if stop_on_event and code is None:
                    return Reply(650, completed)
                self._events.append(completed)
                continue
            if event:
                self._broken = True
                raise ControlError("incomplete asynchronous event in Tor control stream")
            if code is None:
                code = status
            elif status != code:
                self._broken = True
                raise ControlError("mixed status codes in Tor control reply")
            lines.append(line)
            if separator == " ":
                return Reply(code, tuple(lines))

    def _command(self, command: str) -> Reply:
        self._send(command)
        reply = self._read_reply()
        if reply.code != 250:
            detail = " | ".join(reply.texts)[:500]
            raise ControlCommandError(reply.code, detail)
        return reply

    # --------------------------------------------------------- authentication

    def _authenticate(self, protocol: Reply) -> None:
        auth_line = next((t for t in protocol.texts if t.startswith("AUTH ")), None)
        if auth_line is None:
            raise ControlError("PROTOCOLINFO did not advertise control authentication")
        match = _AUTH_RE.match(auth_line)
        if match is None:
            raise ControlError("unable to parse Tor authentication methods")
        methods = {m.strip().upper() for m in match.group("methods").split(",") if m.strip()}
        cookie_token = match.group("cookie")
        policy = self.config.auth
        offered = ", ".join(sorted(methods))

        if policy in {"auto", "safecookie"} and "SAFECOOKIE" in methods:
            if cookie_token is None:
                raise ControlError("SAFECOOKIE was advertised without COOKIEFILE")
            self._authenticate_safecookie(unquote(cookie_token))
            return
        if policy == "safecookie":
            raise ControlError(f"control.auth is pinned to SAFECOOKIE but Tor offered: {offered}")

        if policy in {"auto", "hashedpassword"} and "HASHEDPASSWORD" in methods and self._password:
            # AUTHENTICATE accepts the password as hex, which avoids any quoting ambiguity.
            self._command(f"AUTHENTICATE {self._password.encode('utf-8').hex()}")
            return
        if policy == "hashedpassword":
            if "HASHEDPASSWORD" not in methods:
                raise ControlError(f"control.auth is pinned to HASHEDPASSWORD but Tor offered: {offered}")
            raise ControlError("Tor requires HASHEDPASSWORD auth but no password is configured")

        if "NULL" in methods and self.config.allow_null_auth and policy in {"auto", "null"}:
            self._command("AUTHENTICATE")
            return
        if policy == "null":
            raise ControlError(f"control.auth is pinned to NULL but Tor offered: {offered}")

        if "COOKIE" in methods:
            raise ControlError("Tor only offered deprecated COOKIE auth; enable SAFECOOKIE instead")
        if "HASHEDPASSWORD" in methods:
            raise ControlError("Tor requires HASHEDPASSWORD auth but no password is configured")
        if "NULL" in methods:
            raise ControlError("Tor offered unauthenticated NULL control access; refusing by policy")
        raise ControlError(f"no supported secure Tor control authentication method in [{offered}]")

    def _authenticate_safecookie(self, cookie_path: str) -> None:
        pinned = self.config.cookie_path
        if pinned is not None and os.path.realpath(cookie_path) != os.path.realpath(pinned):
            raise ControlError(
                f"Tor advertised COOKIEFILE {cookie_path!r}, which does not match "
                f"the pinned control.cookie_path {pinned!r}"
            )
        cookie = read_cookie(cookie_path)
        client_nonce = secrets.token_bytes(32)
        challenge = self._command(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        line = next((t for t in challenge.texts if t.startswith("AUTHCHALLENGE ")), None)
        if line is None:
            raise ControlError("Tor SAFECOOKIE challenge reply was incomplete")
        match = _CHALLENGE_RE.match(line)
        if match is None:
            raise ControlError("Tor SAFECOOKIE challenge reply was malformed")
        server_hash = bytes.fromhex(match.group("hash"))
        server_nonce = bytes.fromhex(match.group("nonce"))
        expected_server, client_hash = safe_cookie_hashes(cookie, client_nonce, server_nonce)
        # Mutual authentication: the server must prove knowledge of the cookie *before* we
        # reveal anything derived from it.
        if not hmac.compare_digest(server_hash, expected_server):
            raise ControlError("Tor SAFECOOKIE server proof did not verify")
        self._command(f"AUTHENTICATE {client_hash.hex()}")

    # ------------------------------------------------------------- operations

    def getinfo(self, *keys: str) -> dict[str, str]:
        """Return the requested ``GETINFO`` keys; multi-line values are newline-joined."""
        if not keys or not all(_GETINFO_KEY_RE.fullmatch(k) for k in keys):
            raise ControlError("invalid GETINFO key")
        reply = self._command("GETINFO " + " ".join(keys))
        result: dict[str, str] = {}
        for line in reply.lines:
            if line.data is not None:
                result[line.text.removesuffix("=")] = "\n".join(line.data)
            elif "=" in line.text:
                key, value = line.text.split("=", 1)
                result[key] = value
        return result

    def status(self) -> ControlStatus:
        """Version, bootstrap, liveness, SOCKS listeners and circuit count."""
        try:
            info = self.getinfo(*_STATUS_KEYS)
        except ControlCommandError as exc:
            if exc.code != 552:
                raise
            info = self.getinfo(*_STATUS_KEYS_MINIMAL)

        bootstrap = info.get("status/bootstrap-phase")
        progress_match = _PROGRESS_RE.search(bootstrap or "")
        established = info.get("status/circuit-established")
        raw_listeners = info.get("net/listeners/socks")
        listeners = (
            None
            if raw_listeners is None
            else tuple(unquote(token) for token in _QUOTED_RE.findall(raw_listeners))
        )
        circuits = [c for c in info.get("circuit-status", "").splitlines() if c.strip()]
        return ControlStatus(
            connected=True,
            authenticated=True,
            tor_version=info.get("version"),
            bootstrap_phase=bootstrap,
            bootstrap_progress=int(progress_match.group(1)) if progress_match else None,
            circuit_established=None if established is None else established == "1",
            network_liveness=info.get("network-liveness"),
            socks_listeners=listeners,
            circuit_count=len(circuits),
        )

    def signal_newnym(self) -> NewnymOutcome:
        """Send ``SIGNAL NEWNYM`` and wait for Tor to confirm it actually applied it.

        Tor acknowledges the command with ``250 OK`` and, once it applies the signal, emits
        ``650 SIGNAL NEWNYM``. It sends nothing more for a signal it ignores, and *defers* a
        rate-limited NEWNYM (one per 10 s) instead of dropping it.

        Tor writes the ``250 OK`` before acting on the signal, so any SIGNAL event read
        before that acknowledgement describes earlier activity (another controller's NEWNYM,
        say) and is discarded rather than mistaken for confirmation.

        :raises ControlError: only if Tor did not accept the command.
        """
        self._command("SETEVENTS SIGNAL")
        self._command("SIGNAL NEWNYM")
        accepted_at = self._clock()
        self._events.clear()
        timeout = self.config.signal_event_timeout_seconds
        try:
            event = self._wait_for_event(_is_newnym_event, timeout)
        except ControlError as exc:
            return NewnymOutcome(
                accepted=True,
                applied=False,
                detail=f"control connection failed while awaiting NEWNYM confirmation: {exc}",
            )
        if event is None:
            return NewnymOutcome(
                accepted=True,
                applied=False,
                detail=(
                    f"Tor accepted SIGNAL NEWNYM but did not confirm applying it within "
                    f"{timeout:g}s (ignored, or deferred by Tor's NEWNYM rate limit)"
                ),
            )
        return NewnymOutcome(
            accepted=True,
            applied=True,
            confirmation_seconds=max(0.0, self._clock() - accepted_at),
        )

    def _wait_for_event(
        self,
        predicate: Callable[[tuple[ReplyLine, ...]], bool],
        timeout: float,
    ) -> tuple[ReplyLine, ...] | None:
        deadline = self._clock() + timeout
        while True:
            for index, queued in enumerate(self._events):
                if predicate(queued):
                    del self._events[index]
                    return queued
            self._events.clear()
            if deadline - self._clock() <= 0 or self._socket is None:
                return None
            try:
                reply = self._read_reply(stop_on_event=True, deadline=deadline)
            except ControlTimeoutError:
                return None
            if reply.code != 650:
                self._broken = True
                raise ControlError("unexpected synchronous Tor reply while awaiting an event")
            self._events.append(reply.lines)


def _is_newnym_event(lines: tuple[ReplyLine, ...]) -> bool:
    return bool(lines) and lines[0].text == "SIGNAL NEWNYM"
