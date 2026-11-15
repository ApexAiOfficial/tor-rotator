from __future__ import annotations

import pytest

from fakes import EXIT_A
from tor_rotator.config import CustomProvider
from tor_rotator.providers import (
    BUILTIN_PROVIDERS,
    json_field_parser,
    normalize_ip,
    parse_text,
    parse_torproject,
    resolve,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (EXIT_A, EXIT_A),
        (f"  {EXIT_A}\n", EXIT_A),
        ("::ffff:185.220.101.1", EXIT_A),
        ("2a0b:f4c2::1", "2a0b:f4c2::1"),
    ],
)
def test_normalize_ip_accepts_global_addresses(raw, expected):
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.1",
        "127.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.1.1",
        "203.0.113.5",
        "::1",
        "fe80::1",
        "0.0.0.0",
    ],
)
def test_normalize_ip_rejects_non_global_addresses(raw):
    with pytest.raises(ValueError, match="non-global"):
        normalize_ip(raw)


@pytest.mark.parametrize("raw", ["", "not-an-ip", "1.2.3", "<html>"])
def test_normalize_ip_rejects_garbage(raw):
    with pytest.raises(ValueError, match="not an IP"):
        normalize_ip(raw)


def test_parse_torproject():
    assert parse_torproject(f'{{"IsTor": true, "IP": "{EXIT_A}"}}'.encode()) == (EXIT_A, True)
    assert parse_torproject(f'{{"IsTor": false, "IP": "{EXIT_A}"}}'.encode()) == (EXIT_A, False)


@pytest.mark.parametrize(
    "body",
    [
        f'{{"IsTor": "false", "IP": "{EXIT_A}"}}',  # 1.0.1 read the string "false" as True
        f'{{"IsTor": 1, "IP": "{EXIT_A}"}}',
        f'{{"IP": "{EXIT_A}"}}',
        '{"IsTor": true, "IP": 12345}',
        '{"IsTor": true}',
        "[]",
        "not json",
        "\xff",
    ],
)
def test_parse_torproject_is_strict(body):
    with pytest.raises(ValueError):
        parse_torproject(body.encode("latin-1"))


def test_parse_text():
    assert parse_text(f"{EXIT_A}\n".encode()) == (EXIT_A, None)
    for bad in (b"", b"1.1.1.1 2.2.2.2", b"\xff\xfe"):
        with pytest.raises(ValueError):
            parse_text(bad)


def test_json_field_parser_supports_nesting():
    parser = json_field_parser("data.client.ip")
    assert parser(f'{{"data": {{"client": {{"ip": "{EXIT_A}"}}}}}}'.encode()) == (EXIT_A, None)
    with pytest.raises(ValueError, match="missing"):
        parser(b'{"data": {}}')
    with pytest.raises(ValueError, match="must be a string"):
        parser(b'{"data": {"client": {"ip": 5}}}')


def test_deeply_nested_json_is_a_value_error():
    with pytest.raises(ValueError):
        json_field_parser("ip")(b"[" * 100_000)


def test_builtin_providers_are_https_and_ip_only_endpoints_are_ipv4_hosts():
    for provider in BUILTIN_PROVIDERS.values():
        assert provider.url.startswith("https://")
    assert BUILTIN_PROVIDERS["torproject"].tor_authority
    assert "ipv4." in BUILTIN_PROVIDERS["icanhazip"].url
    assert not any(p.tor_authority for n, p in BUILTIN_PROVIDERS.items() if n != "torproject")


def test_resolve_preserves_order_and_supports_custom_providers():
    custom = (
        CustomProvider("mine", "https://echo.example.test/ip"),
        CustomProvider("mine-json", "https://echo.example.test/json", format="json", json_field="addr"),
    )
    resolved = resolve(["mine", "torproject", "mine-json"], custom)
    assert [p.name for p in resolved] == ["mine", "torproject", "mine-json"]
    assert resolved[0].parser(f"{EXIT_A}".encode()) == (EXIT_A, None)
    assert resolved[2].parser(f'{{"addr": "{EXIT_A}"}}'.encode()) == (EXIT_A, None)
    assert not resolved[0].tor_authority


def test_resolve_rejects_unknown():
    with pytest.raises(KeyError):
        resolve(["nope"])
