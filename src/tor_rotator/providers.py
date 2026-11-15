"""Verification providers: HTTPS endpoints that report the caller's public IP.

The IP-only built-ins use IPv4-only hostnames so that a dual-stack endpoint can never
report a different address family than its peers and cause a false disagreement.
Addresses must be globally routable: an exit never has a private, loopback,
link-local, documentation or otherwise reserved address, so such a reply is rejected.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Final

from .config import TOR_AUTHORITY_PROVIDERS, CustomProvider

Parser = Callable[[bytes], tuple[str, bool | None]]


@dataclass(frozen=True, slots=True)
class Provider:
    """An IP-echo endpoint and how to parse its answer."""

    name: str
    url: str
    parser: Parser
    tor_authority: bool = False


def normalize_ip(value: str) -> str:
    """Parse, canonicalise and validate a reported exit address."""
    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        raise ValueError(f"not an IP address: {candidate[:64]!r}") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global:
        raise ValueError(f"non-global address {address} cannot be a Tor exit")
    return str(address)


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        data = json.loads(body.decode("utf-8"))
    except RecursionError:
        raise ValueError("JSON nesting too deep") from None
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def parse_torproject(body: bytes) -> tuple[str, bool | None]:
    """``{"IsTor": true, "IP": "..."}`` from check.torproject.org."""
    data = _json_object(body)
    is_tor = data.get("IsTor")
    address = data.get("IP")
    # Strict typing: a string such as "false" must never be read as a positive verdict.
    if not isinstance(is_tor, bool):
        raise ValueError("IsTor must be a JSON boolean")
    if not isinstance(address, str):
        raise ValueError("IP must be a JSON string")
    return normalize_ip(address), is_tor


def parse_text(body: bytes) -> tuple[str, bool | None]:
    """A bare address, optionally surrounded by whitespace."""
    try:
        text = body.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ValueError("response is not ASCII text") from None
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("expected exactly one address")
    return normalize_ip(text), None


def json_field_parser(field: str) -> Parser:
    """Parser for a JSON object carrying the address in *field* (dots address nesting)."""

    def parse(body: bytes) -> tuple[str, bool | None]:
        node: Any = _json_object(body)
        for part in field.split("."):
            if not isinstance(node, dict) or part not in node:
                raise ValueError(f"JSON field {field!r} is missing")
            node = node[part]
        if not isinstance(node, str):
            raise ValueError(f"JSON field {field!r} must be a string")
        return normalize_ip(node), None

    return parse


BUILTIN_PROVIDERS: Final[dict[str, Provider]] = {
    "torproject": Provider(
        "torproject",
        "https://check.torproject.org/api/ip",
        parse_torproject,
        tor_authority=True,
    ),
    "ipify": Provider("ipify", "https://api.ipify.org/?format=json", json_field_parser("ip")),
    "icanhazip": Provider("icanhazip", "https://ipv4.icanhazip.com/", parse_text),
    "aws": Provider("aws", "https://checkip.amazonaws.com/", parse_text),
}

if {n for n, p in BUILTIN_PROVIDERS.items() if p.tor_authority} != TOR_AUTHORITY_PROVIDERS:
    raise AssertionError("TOR_AUTHORITY_PROVIDERS is out of sync")  # pragma: no cover


def resolve(names: Iterable[str], custom: Iterable[CustomProvider] = ()) -> tuple[Provider, ...]:
    """Map configured provider names to :class:`Provider` objects, preserving order."""
    custom_by_name = {
        c.name: Provider(
            c.name,
            c.url,
            json_field_parser(c.json_field) if c.format == "json" and c.json_field else parse_text,
        )
        for c in custom
    }
    resolved: list[Provider] = []
    for name in names:
        provider = custom_by_name.get(name) or BUILTIN_PROVIDERS.get(name)
        if provider is None:
            raise KeyError(f"unknown verification provider {name!r}")
        resolved.append(provider)
    return tuple(resolved)
