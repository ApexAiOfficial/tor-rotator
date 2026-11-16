from __future__ import annotations

import ssl
import time

import pytest

from fakes import EXIT_A, EchoResponse
from tor_rotator.errors import ProbeError, ProbeTimeoutError, ProxyError
from tor_rotator.socks import SocksEndpoint
from tor_rotator.transport import MAX_BODY_BYTES, _Deadline, create_ssl_context, https_get


def get(socks, ca_file, url, timeout=5.0, **kwargs):
    return https_get(
        url,
        endpoint=SocksEndpoint.from_config(socks.socks_config()),
        ssl_context=create_ssl_context(ca_file),
        timeout=timeout,
        user_agent="tor-rotator",
        **kwargs,
    )


def test_https_get_through_socks(socks, echo, ca_file):
    response = get(socks, ca_file, "https://ipv4.icanhazip.com/")
    assert response.status == 200
    assert response.body.strip().decode() == EXIT_A
    assert echo.requests[-1]["path"] == "/"


def test_query_string_is_preserved(socks, echo, ca_file):
    get(socks, ca_file, "https://api.ipify.org/?format=json")
    assert echo.requests[-1]["path"] == "/?format=json"


def test_non_200_is_returned_not_raised(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"busy", status=503)
    assert get(socks, ca_file, "https://api.ipify.org/").status == 503


def test_redirects_are_not_followed(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"", status=302, headers={"Location": "https://evil/"})
    response = get(socks, ca_file, "https://api.ipify.org/")
    assert response.status == 302
    assert len(echo.requests) == 1


def test_refuses_plain_http():
    with pytest.raises(ProbeError, match="non-HTTPS"):
        https_get(
            "http://api.ipify.org/",
            endpoint=SocksEndpoint("tcp", "127.0.0.1", 9, "", "u", "p"),
            ssl_context=create_ssl_context(),
            timeout=1,
            user_agent="x",
        )


def test_untrusted_certificate_is_rejected(socks, echo):
    with pytest.raises(ProbeError, match="CERTIFICATE_VERIFY_FAILED"):
        get(socks, None, "https://api.ipify.org/")


def test_hostname_mismatch_is_rejected(socks, echo, ca_file, monkeypatch):
    # The fake certificate does not cover this name, even though the CA is trusted.
    with pytest.raises(ProbeError, match="CERTIFICATE_VERIFY_FAILED|Hostname mismatch"):
        get(socks, ca_file, "https://unlisted.example.test/")


def test_declared_oversize_response_is_rejected(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"x" * (MAX_BODY_BYTES + 1))
    with pytest.raises(ProbeError, match="declared"):
        get(socks, ca_file, "https://api.ipify.org/")


def test_undeclared_oversize_response_is_rejected(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"x" * (MAX_BODY_BYTES + 5000), chunked=True)
    with pytest.raises(ProbeError, match="exceeded"):
        get(socks, ca_file, "https://api.ipify.org/")


def test_custom_body_limit(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"0123456789", chunked=True)
    with pytest.raises(ProbeError, match="10-byte|9-byte"):
        get(socks, ca_file, "https://api.ipify.org/", max_body=9)


def test_total_deadline_defeats_slow_drip(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"x" * 200, drip_delay=0.05)
    started = time.monotonic()
    with pytest.raises(ProbeTimeoutError, match="deadline"):
        get(socks, ca_file, "https://api.ipify.org/", timeout=0.8)
    assert time.monotonic() - started < 3.0


def test_proxy_errors_pass_through(short_tmp):
    from fakes import FakeSocks

    with FakeSocks(short_tmp, reply=0x04) as fake, pytest.raises(ProxyError, match="host unreachable"):
        https_get(
            "https://api.ipify.org/",
            endpoint=SocksEndpoint.from_config(fake.socks_config()),
            ssl_context=create_ssl_context(),
            timeout=3,
            user_agent="x",
        )


def test_create_ssl_context_enforces_verification():
    context = create_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_deadline_guard_after_expiry_shuts_socket_immediately():
    import socket

    a, b = socket.socketpair()
    with a, b:
        deadline = _Deadline(0.01)
        with deadline:
            time.sleep(0.1)
            assert deadline.fired
            deadline.guard(a)
            assert a.recv(1) == b""
            with pytest.raises(ProbeTimeoutError):
                deadline.remaining()


def test_total_deadline_covers_socks_negotiation():
    import socket
    import threading

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    done = threading.Event()

    def trickle() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05")  # half a greeting, then stall
            done.wait(5)

    thread = threading.Thread(target=trickle)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(ProbeTimeoutError):
            https_get(
                "https://api.ipify.org/",
                endpoint=SocksEndpoint("tcp", "127.0.0.1", listener.getsockname()[1], "", "u", "p"),
                ssl_context=create_ssl_context(),
                timeout=0.5,
                user_agent="x",
            )
        assert time.monotonic() - started < 2.0
    finally:
        done.set()
        thread.join(5)
        listener.close()


def test_truncated_response_is_rejected(socks, echo, ca_file):
    echo.responses["api.ipify.org"] = EchoResponse(b"185.220.10", headers={"Content-Length": "13"})
    with pytest.raises(ProbeError, match="truncated|EOF|IncompleteRead"):
        get(socks, ca_file, "https://api.ipify.org/")
