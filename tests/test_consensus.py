"""Consensus rules, including regressions for the 1.0.1 exit-IP consensus bug."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from fakes import EXIT_A, EXIT_B, EXIT_C
from tor_rotator.consensus import evaluate
from tor_rotator.models import ProviderObservation as Obs


def tor(ip: str, is_tor: bool = True) -> Obs:
    return Obs("torproject", ok=True, ip=ip, is_tor=is_tor)


def plain(name: str, ip: str) -> Obs:
    return Obs(name, ok=True, ip=ip)


def failed(name: str) -> Obs:
    return Obs(name, ok=False, error="down")


def run(observations: list[Obs], quorum: int = 2, unanimous: bool = True, require_tor: bool = True):
    return evaluate(
        observations,
        quorum=quorum,
        require_unanimous=unanimous,
        require_tor_confirmation=require_tor,
    )


def test_unanimous_tor_confirmed_consensus_is_ok():
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_A), plain("icanhazip", EXIT_A)])
    assert outcome.ok
    assert outcome.ip == EXIT_A
    assert (outcome.agreeing, outcome.dissenting, outcome.responded) == (3, 0, 3)
    assert outcome.tor_confirmed is True
    assert outcome.error is None


# --- Regression: 1.0.1 computed tor_confirmed over *all* votes, unbound to the consensus IP.


def test_regression_tor_confirmation_for_other_ip_does_not_vouch_for_consensus_strict():
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_B), plain("icanhazip", EXIT_B)])
    assert not outcome.ok
    assert outcome.ip is None
    assert outcome.candidate_ip == EXIT_B
    assert outcome.tor_confirmed is None
    assert "disagree" in (outcome.error or "")
    assert "not positively confirmed for the consensus IP" in (outcome.error or "")


def test_regression_tor_confirmation_is_bound_even_in_majority_mode():
    # 1.0.1 reported ok=True, ip=B, tor_confirmed=True here, but B was never confirmed as Tor.
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_B), plain("icanhazip", EXIT_B)], unanimous=False)
    assert not outcome.ok
    assert outcome.tor_confirmed is None
    assert outcome.error == "Tor route was not positively confirmed for the consensus IP"


def test_regression_tie_is_never_resolved_arbitrarily():
    # 1.0.1 picked whichever IP Counter.most_common happened to return first.
    outcome = run([plain("ipify", EXIT_A), plain("icanhazip", EXIT_B)], quorum=1, require_tor=False)
    assert not outcome.ok
    assert outcome.candidate_ip is None
    assert outcome.agreeing == 0
    assert "no majority" in (outcome.error or "")


def test_majority_mode_accepts_dissent_when_consensus_is_confirmed():
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_A), plain("icanhazip", EXIT_B)], unanimous=False)
    assert outcome.ok
    assert outcome.ip == EXIT_A
    assert outcome.dissenting == 1


def test_strict_mode_rejects_any_dissent():
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_A), plain("icanhazip", EXIT_B)])
    assert not outcome.ok
    assert outcome.candidate_ip == EXIT_A
    assert "icanhazip=" in (outcome.error or "")


def test_tor_negative_is_fatal_even_without_required_confirmation():
    outcome = run([tor(EXIT_A, is_tor=False), plain("ipify", EXIT_A)], require_tor=False)
    assert not outcome.ok
    assert outcome.tor_confirmed is False
    assert "Tor-negative" in (outcome.error or "")


def test_tor_negative_for_dissenting_ip_is_still_fatal():
    outcome = run(
        [tor(EXIT_C, is_tor=False), plain("ipify", EXIT_A), plain("icanhazip", EXIT_A)],
        unanimous=False,
        require_tor=False,
    )
    assert not outcome.ok
    assert outcome.tor_confirmed is False


def test_quorum_not_met_with_failures():
    outcome = run([tor(EXIT_A), failed("ipify"), failed("icanhazip")])
    assert not outcome.ok
    assert outcome.candidate_ip == EXIT_A
    assert "quorum not met (1/2)" in (outcome.error or "")


def test_provider_failure_tolerated_when_quorum_met():
    outcome = run([tor(EXIT_A), failed("ipify"), plain("icanhazip", EXIT_A)])
    assert outcome.ok
    assert outcome.responded == 2


def test_no_successful_provider():
    outcome = run([failed("a"), failed("b")])
    assert not outcome.ok
    assert outcome.responded == 0
    assert outcome.error == "no verification provider returned a valid IP"


def test_unconfirmed_without_requirement_is_ok():
    outcome = run([plain("ipify", EXIT_A), plain("icanhazip", EXIT_A)], require_tor=False)
    assert outcome.ok
    assert outcome.tor_confirmed is None


def test_tie_without_tor_requirement_reports_generic_confirmation_message():
    outcome = run([tor(EXIT_A), plain("ipify", EXIT_B)], quorum=1)
    assert not outcome.ok
    assert "Tor route was not positively confirmed" in (outcome.error or "")


# --- Property-based invariants -------------------------------------------------------

_ips = st.sampled_from([EXIT_A, EXIT_B, EXIT_C])


@st.composite
def observation_sets(draw: st.DrawFn) -> list[Obs]:
    count = draw(st.integers(min_value=1, max_value=5))
    observations = []
    for index in range(count):
        name = "torproject" if index == 0 else f"p{index}"
        if draw(st.booleans()) and draw(st.booleans()):
            observations.append(failed(name))
            continue
        ip = draw(_ips)
        is_tor = draw(st.sampled_from([True, False])) if index == 0 else None
        observations.append(Obs(name, ok=True, ip=ip, is_tor=is_tor))
    return observations


@given(
    observation_sets(),
    st.integers(min_value=1, max_value=5),
    st.booleans(),
    st.booleans(),
)
def test_consensus_invariants(observations, quorum, unanimous, require_tor):
    outcome = run(observations, quorum=quorum, unanimous=unanimous, require_tor=require_tor)
    successes = [o for o in observations if o.ok]
    if outcome.ok:
        assert outcome.ip is not None
        assert outcome.ip == outcome.candidate_ip
        assert outcome.agreeing >= quorum
        assert sum(o.ip == outcome.ip for o in successes) == outcome.agreeing
        assert not any(o.is_tor is False for o in successes)
        if unanimous:
            assert outcome.dissenting == 0
        if require_tor:
            assert any(o.is_tor is True and o.ip == outcome.ip for o in successes)
    else:
        assert outcome.ip is None
        assert outcome.error
    assert outcome.agreeing + outcome.dissenting == outcome.responded == len(successes)
