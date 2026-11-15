from __future__ import annotations

import os
import socket
import threading
import time
from contextlib import closing

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fakes import FakeTorControl, spec_hashes, tor_escape
from tor_rotator.config import ControlConfig
from tor_rotator.control import (
    MAX_LINE_BYTES,
    TorControlClient,
    read_cookie,
    safe_cookie_hashes,
    unquote,
)
from tor_rotator.errors import ControlCommandError, ControlError

# --- QuotedString decoding -------------------------------------------------------------


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (r'"/run/tor/control.authcookie"', "/run/tor/control.authcookie"),
        (r'"a\\b"', "a\\b"),
        (r'"say \"hi\""', 'say "hi"'),
        (r'"tab\there"', "tab\there"),
        (r'"nl\nend"', "nl\nend"),
        (r'"cr\r"', "cr\r"),
        (r'"q\'"', "q'"),
        (r'"oct\101\0"', "octA\x00"),
        (r'"lit\z"', "litz"),
        ('""', ""),
    ],
)
def test_unquote(token, expected):
    assert unquote(token) == expected


@pytest.mark.parametrize("token", ['"unterminated', "noquotes", '"a"b"', '"dangling\\"'[:-1], r'"\777"'])
def test_unquote_rejects_malformed(token):
    with pytest.raises(ControlError):
        unquote(token)


@given(st.text(alphabet=st.characters(codec="utf-8", exclude_categories=["Cs"]), max_size=40))
def test_unquote_round_trips_tor_escaping(text):
    assert unquote(f'"{tor_escape(text)}"') == text


def test_unquote_does_not_evaluate_python_escapes():
    # 1.0.1 used ast.literal_eval, which would decode these as Python escapes.
    backslash = chr(92)
    token = '"' + backslash + "x41" + backslash + "u0041" + '"'
    assert unquote(token) == "x41u0041"


# --- SAFECOOKIE primitives --------------------------------------------------------------


def test_safecookie_hashes_match_spec():
    cookie, cn, sn = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
    assert safe_cookie_hashes(cookie, cn, sn) == spec_hashes(cookie, cn, sn)


def test_read_cookie(tmp_path):
    good = tmp_path / "cookie"
    good.write_bytes(os.urandom(32))
    assert read_cookie(str(good)) == good.read_bytes()
    short = tmp_path / "short"
    short.write_bytes(b"x")
    with pytest.raises(ControlError, match="exactly 32"):
        read_cookie(str(short))
    long = tmp_path / "long"
    long.write_bytes(os.urandom(33))
    with pytest.raises(ControlError, match="exactly 32"):
        read_cookie(str(long))


def test_read_cookie_refuses_symlink_dir_relative_and_missing(tmp_path):
    target = tmp_path / "real"
    target.write_bytes(os.urandom(32))
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ControlError, match="cannot open"):
        read_cookie(str(link))
    with pytest.raises(ControlError, match="not a regular file"):
        read_cookie(str(tmp_path))
    with pytest.raises(ControlError, match="absolute"):
        read_cookie("relative/cookie")
    with pytest.raises(ControlError, match="cannot open"):
        read_cookie(str(tmp_path / "missing"))


# --- Reply parsing over a real socket pair -----------------------------------------------


def wired(transcript: bytes, **config: object) -> tuple[TorControlClient, socket.socket]:
    ours, theirs = socket.socketpair()
    client = TorControlClient(ControlConfig(**config))  # type: ignore[arg-type]
    client._attach(ours)
    ours.settimeout(2)
    theirs.sendall(transcript)
    return client, theirs


def test_reply_with_events_data_block_and_dot_unstuffing():
    client, peer = wired(
        b"650 SIGNAL NEWNYM\r\n"
        b"250-version=0.4.8.16\r\n"
        b"250+circuit-status=\r\n"
        b"1 BUILT $A~a PURPOSE=GENERAL\r\n"
        b"..leading-dot\r\n"
        b".\r\n"
        b"250 OK\r\n"
    )
    with peer, closing(client):
        reply = client._read_reply()
        assert reply.code == 250
        assert reply.texts[-1] == "OK"
        assert reply.lines[1].data == ("1 BUILT $A~a PURPOSE=GENERAL", ".leading-dot")
        assert client._events == [(reply.lines[0].__class__(650, " ", "SIGNAL NEWNYM"),)]


@pytest.mark.parametrize(
    ("transcript", "message"),
    [
        (b"nonsense\r\n", "malformed"),
        (b"250-a\r\n251 b\r\n", "mixed status"),
        (b"650-EVENT start\r\n250 OK\r\n", "incomplete asynchronous event"),
        (b"250 \xff\xfe\r\n", "UTF-8"),
        (b"250 no newline", "mid-line"),
        (b"", "closed unexpectedly"),
        (b"250-" + b"x" * (MAX_LINE_BYTES + 10) + b"\r\n", "safety limit"),
    ],
)
def test_reply_parser_fails_closed(transcript, message):
    client, peer = wired(transcript)
    if not transcript.endswith(b"\n"):
        peer.shutdown(socket.SHUT_WR)
    with peer, closing(client):
        with pytest.raises(ControlError, match=message):
            client._read_reply()
        with pytest.raises(ControlError, match="not usable"):
            client._command("GETINFO version")


def test_command_rejects_non_250_and_multiline_input():
    client, peer = wired(b"552 Unrecognized signal\r\n")
    with peer, closing(client):
        with pytest.raises(ControlCommandError, match="552") as info:
            client._command("SIGNAL BOGUS")
        assert info.value.code == 552
        assert peer.recv(100) == b"SIGNAL BOGUS\r\n"
        with pytest.raises(ControlError, match="single-line"):
            client._send("GETINFO version\r\nQUIT")


def test_send_failure_marks_connection_broken():
    client, peer = wired(b"")
    peer.close()
    client._socket.close()  # type: ignore[union-attr]
    with pytest.raises(ControlError, match="unable to send"):
        client._send("GETINFO version")
    client.close()


def test_close_is_idempotent():
    client, peer = wired(b"")
    with peer:
        client.close()
        client.close()
        assert client._socket is None


def test_getinfo_rejects_bad_keys():
    client, peer = wired(b"")
    with peer, closing(client):
        with pytest.raises(ControlError, match="invalid GETINFO key"):
            client.getinfo("bad key")
        with pytest.raises(ControlError, match="invalid GETINFO key"):
            client.getinfo()


# --- Full sessions against the fake control port ----------------------------------------


@pytest.mark.parametrize("unix", [False, True])
def test_safecookie_session_and_status(short_tmp, unix):
    with FakeTorControl(short_tmp, unix=unix) as fake, TorControlClient(fake.control_config()) as tor:
        status = tor.status()
    assert status.connected and status.authenticated
    assert status.tor_version == "0.4.8.16"
    assert status.bootstrap_progress == 100
    assert status.circuit_established is True
    assert status.network_liveness == "up"
    assert status.socks_listeners == ("127.0.0.1:9050",)
    assert status.circuit_count == 2
    assert fake.commands[0] == "PROTOCOLINFO 1"
    assert fake.commands[1].startswith("AUTHCHALLENGE SAFECOOKIE ")


def test_status_falls_back_on_older_tor(short_tmp):
    with FakeTorControl(short_tmp) as fake:
        del fake.getinfo["network-liveness"]
        with TorControlClient(fake.control_config()) as tor:
            status = tor.status()
    assert status.network_liveness is None
    assert status.socks_listeners is None
    assert status.circuit_established is None
    assert status.bootstrap_progress == 100


def test_status_propagates_other_errors(short_tmp):
    with FakeTorControl(short_tmp) as fake:
        for key in list(fake.getinfo):
            del fake.getinfo[key]
        with TorControlClient(fake.control_config()) as tor, pytest.raises(ControlCommandError):
            tor.status()


def test_cookie_path_with_special_characters(tmp_path):
    directory = tmp_path / 'we"ird\\dir'
    directory.mkdir()
    with FakeTorControl(directory) as fake, TorControlClient(fake.control_config()) as tor:
        assert tor.status().connected


def test_cookie_pin_mismatch_is_refused(short_tmp):
    with FakeTorControl(short_tmp) as fake:
        config = fake.control_config(cookie_path="/var/run/elsewhere/cookie")
        with pytest.raises(ControlError, match="does not match"):
            TorControlClient(config).__enter__()


def test_cookie_pin_match_is_accepted(short_tmp):
    with FakeTorControl(short_tmp) as fake:
        config = fake.control_config(cookie_path=str(fake.cookie_path))
        with TorControlClient(config) as tor:
            assert tor.status().connected


def test_server_impersonation_is_detected_before_proof_is_sent(short_tmp):
    with FakeTorControl(short_tmp, bad_server_hash=True) as fake:
        with pytest.raises(ControlError, match="server proof did not verify"):
            TorControlClient(fake.control_config()).__enter__()
        assert not any(c.startswith("AUTHENTICATE") for c in fake.commands)


def test_hashed_password_auth_sends_hex(short_tmp):
    with FakeTorControl(short_tmp, methods=("HASHEDPASSWORD",), password="s3cr3t pass") as fake:
        with TorControlClient(fake.control_config(), password="s3cr3t pass") as tor:
            assert tor.status().connected
        assert f"AUTHENTICATE {b's3cr3t pass'.hex()}" in fake.commands
        assert not any("s3cr3t" in c for c in fake.commands)


def test_wrong_password_is_rejected(short_tmp):
    with FakeTorControl(short_tmp, methods=("HASHEDPASSWORD",), password="right") as fake:
        with pytest.raises(ControlCommandError, match="515"):
            TorControlClient(fake.control_config(), password="wrong").__enter__()


def test_null_auth_requires_opt_in(short_tmp):
    with FakeTorControl(short_tmp, methods=("NULL",)) as fake:
        with pytest.raises(ControlError, match="NULL"):
            TorControlClient(fake.control_config()).__enter__()
        with TorControlClient(fake.control_config(allow_null_auth=True)) as tor:
            assert tor.status().connected


@pytest.mark.parametrize(
    ("methods", "config", "password", "message"),
    [
        (("HASHEDPASSWORD",), {"auth": "safecookie"}, None, "pinned to SAFECOOKIE"),
        (("SAFECOOKIE",), {"auth": "hashedpassword"}, "pw", "pinned to HASHEDPASSWORD"),
        (("HASHEDPASSWORD",), {"auth": "hashedpassword"}, None, "no password"),
        (("SAFECOOKIE",), {"auth": "null", "allow_null_auth": True}, None, "pinned to NULL"),
        (("COOKIE",), {}, None, "deprecated COOKIE"),
        (("HASHEDPASSWORD",), {}, None, "no password"),
        (("FUTURE",), {}, None, "no supported secure"),
    ],
)
def test_authentication_policy(short_tmp, methods, config, password, message):
    with FakeTorControl(short_tmp, methods=methods, password="pw") as fake:
        with pytest.raises(ControlError, match=message):
            TorControlClient(fake.control_config(**config), password=password).__enter__()


def test_password_pin_prevents_downgrade_to_password(short_tmp):
    # A fake "Tor" offering only HASHEDPASSWORD never receives the password when pinned.
    with FakeTorControl(short_tmp, methods=("HASHEDPASSWORD",), password="pw") as fake:
        with pytest.raises(ControlError):
            TorControlClient(fake.control_config(auth="safecookie"), password=None).__enter__()
        assert not any(c.startswith("AUTHENTICATE") for c in fake.commands)


@pytest.mark.parametrize(
    ("script", "message"),
    [
        (b"250-PROTOCOLINFO 1\r\n250 OK\r\n", "did not advertise"),
        (b"250-PROTOCOLINFO 1\r\n250-AUTH WHAT\r\n250 OK\r\n", "unable to parse"),
        (b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE\r\n250 OK\r\n", "without COOKIEFILE"),
    ],
)
def test_protocolinfo_parsing_fails_closed(short_tmp, script, message):
    with FakeTorControl(short_tmp, raw_script=script) as fake:
        with pytest.raises(ControlError, match=message):
            TorControlClient(fake.control_config()).__enter__()


def test_challenge_reply_validation(short_tmp, monkeypatch):
    client, peer = wired(b"250 AUTHCHALLENGE SERVERHASH=zz SERVERNONCE=yy\r\n")
    cookie = short_tmp / "cookie"
    cookie.write_bytes(os.urandom(32))
    with peer, closing(client), pytest.raises(ControlError, match="malformed"):
        client._authenticate_safecookie(str(cookie))
    client, peer = wired(b"250 OK\r\n")
    with peer, closing(client), pytest.raises(ControlError, match="incomplete"):
        client._authenticate_safecookie(str(cookie))


def test_connection_refused_and_non_loopback(short_tmp, monkeypatch):
    unused = socket.socket()
    unused.bind(("127.0.0.1", 0))
    port = unused.getsockname()[1]
    unused.close()
    with pytest.raises(ControlError, match="cannot connect"):
        TorControlClient(ControlConfig(port=port, connect_timeout_seconds=1)).__enter__()

    def resolve_elsewhere(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.7", port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve_elsewhere)
    with pytest.raises(ControlError, match="not loopback"):
        TorControlClient(ControlConfig(host="localhost")).__enter__()


def test_unresolvable_host(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ControlError, match="cannot resolve"):
        TorControlClient(ControlConfig(host="localhost")).__enter__()


def test_missing_unix_socket(short_tmp):
    config = ControlConfig(mode="unix", socket_path=str(short_tmp / "absent.sock"))
    with pytest.raises(ControlError, match="cannot connect"):
        TorControlClient(config).__enter__()


def test_unexpected_os_error_during_handshake_is_wrapped(short_tmp, monkeypatch):
    with FakeTorControl(short_tmp) as fake:

        def boom(self, protocol):
            raise OSError("synthetic")

        monkeypatch.setattr(TorControlClient, "_authenticate", boom)
        with pytest.raises(ControlError, match="synthetic"):
            TorControlClient(fake.control_config()).__enter__()


# --- NEWNYM confirmation ----------------------------------------------------------------


def newnym(short_tmp, mode, delay=0.0, timeout=1.0):
    with FakeTorControl(short_tmp, newnym=mode, newnym_delay=delay) as fake:
        with TorControlClient(fake.control_config(signal_event_timeout_seconds=timeout)) as tor:
            outcome = tor.signal_newnym()
        return outcome, fake.commands


def test_newnym_confirmed_immediately(short_tmp):
    outcome, commands = newnym(short_tmp, "immediate")
    assert outcome.accepted and outcome.applied
    assert outcome.confirmation_seconds is not None and outcome.confirmation_seconds < 1
    assert commands[-2:] == ["SETEVENTS SIGNAL", "SIGNAL NEWNYM"]


def test_newnym_event_before_acknowledgement_is_not_confirmation(short_tmp):
    # An event that precedes Tor's 250 belongs to earlier activity (e.g. another controller).
    outcome, _ = newnym(short_tmp, "stale", timeout=0.3)
    assert outcome.accepted and not outcome.applied
    assert "did not confirm" in (outcome.detail or "")


def test_newnym_ignored_is_reported(short_tmp):
    outcome, _ = newnym(short_tmp, "ignored", timeout=0.3)
    assert outcome.accepted and not outcome.applied
    assert "rate limit" in (outcome.detail or "")


def test_deferred_newnym_is_confirmed_within_timeout(short_tmp):
    outcome, _ = newnym(short_tmp, "delayed", delay=0.4, timeout=3.0)
    assert outcome.applied
    assert outcome.confirmation_seconds is not None and outcome.confirmation_seconds >= 0.3


def test_newnym_confirmed_after_unrelated_events(short_tmp):
    outcome, _ = newnym(short_tmp, "noise")
    assert outcome.applied


def test_newnym_connection_drop_is_not_applied(short_tmp):
    outcome, _ = newnym(short_tmp, "drop")
    assert outcome.accepted and not outcome.applied
    assert "connection failed" in (outcome.detail or "")


def test_newnym_protocol_violation_is_not_applied(short_tmp):
    outcome, _ = newnym(short_tmp, "spurious")
    assert not outcome.applied
    assert "unexpected synchronous" in (outcome.detail or "")


def test_newnym_rejected_raises(short_tmp):
    with FakeTorControl(short_tmp, newnym="reject") as fake, TorControlClient(fake.control_config()) as tor:
        with pytest.raises(ControlCommandError):
            tor.signal_newnym()


def test_event_wait_returns_none_without_socket():
    client = TorControlClient(ControlConfig())
    assert client._wait_for_event(lambda _lines: True, 1.0) is None


def test_concurrent_clients_are_independent(short_tmp):
    results: list[bool] = []
    with FakeTorControl(short_tmp) as fake:

        def worker() -> None:
            with TorControlClient(fake.control_config()) as tor:
                results.append(tor.signal_newnym().applied)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
    assert results == [True] * 4


def test_dangling_escape_inside_quotes():
    with pytest.raises(ControlError, match="dangling"):
        unquote('"abc\\"')


def test_read_error_and_total_reply_limit(monkeypatch):
    client, peer = wired(b"")
    with peer, closing(client):
        peer.close()

        class Exploding:
            def settimeout(self, value):
                return None

            def recv(self, size):
                raise OSError("reset by peer")

            def close(self):
                return None

        client._socket = Exploding()  # type: ignore[assignment]
        client._deadline = time.monotonic() + 5
        with pytest.raises(ControlError, match="reset by peer"):
            client._readline()
        with pytest.raises(ControlError, match="not usable"):
            client._readline()

    monkeypatch.setattr("tor_rotator.control.MAX_REPLY_BYTES", 32)
    client, peer = wired(b"250-" + b"a" * 20 + b"\r\n250-" + b"b" * 20 + b"\r\n250 OK\r\n")
    with peer, closing(client), pytest.raises(ControlError, match="reply exceeded"):
        client._read_reply()


def test_status_reraises_non_552_errors(monkeypatch):
    client = TorControlClient(ControlConfig())

    def fail(*keys):
        raise ControlCommandError(551, "internal error")

    monkeypatch.setattr(client, "getinfo", fail)
    with pytest.raises(ControlCommandError, match="551"):
        client.status()
