from __future__ import annotations

import json

import pytest

from fakes import EXIT_A, EXIT_B, EchoResponse
from tor_rotator.config import SocksConfig, VerifyConfig
from tor_rotator.errors import ConfigurationError, ProbeTimeoutError
from tor_rotator.transport import HttpResponse
from tor_rotator.verify import USER_AGENT, ExitIpVerifier, ExitVerifier


def fetcher(answers):
    def fetch(url):
        for marker, answer in answers.items():
            if marker in url:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise AssertionError(url)

    return fetch


def ok(body: str) -> HttpResponse:
    return HttpResponse(200, "OK", body.encode())


def standard(ip_tor=EXIT_A, ip_ipify=EXIT_A, ip_text=EXIT_A, is_tor=True):
    return {
        "torproject": ok(json.dumps({"IsTor": is_tor, "IP": ip_tor})),
        "ipify": ok(json.dumps({"ip": ip_ipify})),
        "icanhazip": ok(ip_text + "\n"),
    }


def test_verifier_reaches_unanimous_tor_confirmed_consensus():
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetcher(standard())).verify()
    assert result.ok
    assert result.ip == EXIT_A
    assert result.agreeing == 3
    assert result.tor_confirmed is True
    assert result.duration_ms is not None
    assert [o.provider for o in result.observations] == ["torproject", "ipify", "icanhazip"]
    json.dumps(result.to_dict())


def test_regression_consensus_bug_through_the_verifier():
    answers = standard(ip_tor=EXIT_A, ip_ipify=EXIT_B, ip_text=EXIT_B)
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetcher(answers)).verify()
    assert not result.ok
    assert result.ip is None
    assert result.candidate_ip == EXIT_B


def test_probe_failures_become_observations():
    answers = standard()
    answers["ipify"] = ProbeTimeoutError("probe exceeded its 15s deadline")
    answers["icanhazip"] = HttpResponse(503, "Service Unavailable", b"")
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetcher(answers)).verify()
    assert not result.ok
    errors = {o.provider: o.error for o in result.observations if not o.ok}
    assert "ProbeTimeoutError" in errors["ipify"]
    assert "HTTP 503" in errors["icanhazip"]
    assert all(o.latency_ms is not None for o in result.observations)


def test_unparseable_answer_is_an_observation_error():
    answers = standard()
    answers["icanhazip"] = ok("<html>blocked</html>")
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetcher(answers)).verify()
    assert result.ok  # 2 of 3 agree, the third failed rather than dissented
    assert result.responded == 2


def test_alias_is_preserved():
    assert ExitIpVerifier is ExitVerifier


def test_provider_names():
    verifier = ExitVerifier(SocksConfig(), VerifyConfig(providers=("ipify", "torproject")))
    assert verifier.provider_names == ("ipify", "torproject")


def test_bad_ca_file_is_a_configuration_error(tmp_path):
    bad = tmp_path / "ca.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ConfigurationError, match="trust store"):
        ExitVerifier(SocksConfig(), VerifyConfig(ca_file=str(bad)))


# --- End to end through the fake SOCKS proxy and TLS echo servers ------------------------


def test_end_to_end_verification_over_socks(socks, echo, ca_file):
    verifier = ExitVerifier(socks.socks_config(), VerifyConfig(ca_file=ca_file, timeout_seconds=5))
    result = verifier.verify()
    assert result.ok, result.error
    assert result.ip == EXIT_A
    # Hostnames reach the proxy as domain names: no local DNS resolution.
    assert {r["atyp"] for r in socks.requests} == {0x03}
    assert {r["host"] for r in socks.requests} == {
        "check.torproject.org",
        "api.ipify.org",
        "ipv4.icanhazip.com",
    }
    # One stable isolation credential pair for every probe.
    assert {(r["username"], r["password"]) for r in socks.requests} == {
        ("tor-rotator-probe", "fixed-probe-isolation")
    }
    assert {r["user_agent"] for r in echo.requests} == {USER_AGENT}


def test_end_to_end_detects_split_exit(socks, echo, ca_file):
    echo.answer(torproject=(EXIT_A, True), ipify=EXIT_B, icanhazip=EXIT_B)
    result = ExitVerifier(socks.socks_config(), VerifyConfig(ca_file=ca_file, timeout_seconds=5)).verify()
    assert not result.ok
    assert result.tor_confirmed is None


def test_end_to_end_rejects_untrusted_certificate(socks, echo):
    # No ca_file: the fake servers' certificates are not in the system trust store.
    result = ExitVerifier(socks.socks_config(), VerifyConfig(timeout_seconds=5)).verify()
    assert not result.ok
    assert all("CERTIFICATE_VERIFY_FAILED" in (o.error or "") for o in result.observations)


def test_end_to_end_custom_provider(socks, echo, ca_file):
    from tor_rotator.config import CustomProvider

    echo.responses["echo.example.test"] = EchoResponse(f'{{"client": {{"ip": "{EXIT_A}"}}}}'.encode())
    config = VerifyConfig(
        ca_file=ca_file,
        timeout_seconds=5,
        quorum=2,
        providers=("torproject", "mine"),
        custom_providers=(
            CustomProvider("mine", "https://echo.example.test/whoami", format="json", json_field="client.ip"),
        ),
    )
    result = ExitVerifier(socks.socks_config(), config).verify()
    assert result.ok, result.error
    assert any(r["path"] == "/whoami" for r in echo.requests)


# --- Re-sampling on disagreement (observed live: Tor can move one stream to another circuit)


class Rounds:
    def __init__(self, *rounds):
        self.rounds = list(rounds)
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        current = self.rounds[0] if len(self.rounds) == 1 else self.rounds[(self.calls - 1) // 3]
        return fetcher(current)(url)


def test_split_round_is_resampled_and_converges():
    rounds = Rounds(
        standard(ip_tor=EXIT_A, ip_ipify=EXIT_B, ip_text=EXIT_B), standard(EXIT_B, EXIT_B, EXIT_B)
    )
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=rounds).verify()
    assert result.ok
    assert result.ip == EXIT_B
    assert result.rounds == 2
    assert rounds.calls == 6


def test_persistent_split_fails_after_max_rounds():
    rounds = Rounds(standard(ip_tor=EXIT_A, ip_ipify=EXIT_A, ip_text=EXIT_B))
    result = ExitVerifier(SocksConfig(), VerifyConfig(max_rounds=3), fetch=rounds).verify()
    assert not result.ok
    assert result.rounds == 3
    assert rounds.calls == 9


def test_tor_negative_is_never_resampled():
    rounds = Rounds(standard(ip_tor=EXIT_A, ip_ipify=EXIT_B, ip_text=EXIT_B, is_tor=False))
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=rounds).verify()
    assert not result.ok
    assert result.rounds == 1


def test_provider_failures_are_not_resampled():
    answers = standard()
    answers["ipify"] = ProbeTimeoutError("deadline")
    answers["icanhazip"] = ProbeTimeoutError("deadline")
    result = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetcher(answers)).verify()
    assert not result.ok
    assert result.rounds == 1


def test_single_round_configuration():
    rounds = Rounds(standard(ip_tor=EXIT_A, ip_ipify=EXIT_A, ip_text=EXIT_B))
    result = ExitVerifier(SocksConfig(), VerifyConfig(max_rounds=1), fetch=rounds).verify()
    assert result.rounds == 1
    assert rounds.calls == 3


def test_ca_file_must_be_safe(tmp_path, ca_file):
    import shutil

    unsafe = tmp_path / "ca.pem"
    shutil.copy(ca_file, unsafe)
    unsafe.chmod(0o666)
    with pytest.raises(ConfigurationError, match="world-writable"):
        ExitVerifier(SocksConfig(), VerifyConfig(ca_file=str(unsafe)))
    with pytest.raises(ConfigurationError, match="not a regular file"):
        ExitVerifier(SocksConfig(), VerifyConfig(ca_file=str(tmp_path)))
    with pytest.raises(ConfigurationError, match="trust store"):
        ExitVerifier(SocksConfig(), VerifyConfig(ca_file=str(tmp_path / "missing.pem")))
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="exceeds"):
        ExitVerifier(SocksConfig(), VerifyConfig(ca_file=str(big)))


def test_only_tor_authoritative_providers_can_vouch_for_tor():
    from tor_rotator.providers import Provider

    config = VerifyConfig(require_tor_confirmation=False, quorum=1, providers=("ipify",))
    verifier = ExitVerifier(SocksConfig(), config, fetch=fetcher({"impostor": ok("x")}))
    verifier._providers = (Provider("impostor", "https://impostor/", lambda body: (EXIT_A, True)),)
    result = verifier.verify()
    assert result.observations[0].is_tor is None
    assert result.tor_confirmed is None


def test_cancellation_stops_probing_between_providers():
    calls = []

    def fetch(url):
        calls.append(url)
        return standard()[next(k for k in ("torproject", "ipify", "icanhazip") if k in url)]

    verifier = ExitVerifier(SocksConfig(), VerifyConfig(), fetch=fetch, cancelled=lambda: len(calls) >= 1)
    result = verifier.verify()
    assert len(calls) == 1
    assert [o.error for o in result.observations[1:]] == ["cancelled: stop requested"] * 2
    assert result.rounds == 1
