"""Exit-IP consensus: a pure function over provider observations.

Rules, in order of severity:

1. **Tor-negative is fatal.** If any Tor-authoritative provider reports ``IsTor=false``,
   some traffic left through a non-Tor path. Verification fails, whatever the vote.
2. **The consensus must be unambiguous.** The consensus IP is the address with strictly
   more votes than any other. A tie means there is no consensus, never an arbitrary pick.
3. **Quorum.** At least ``quorum`` providers must report the consensus IP.
4. **Unanimity** (default). With ``require_unanimous``, any responding provider that
   reports a *different* address fails verification. Probes share one isolation
   bucket, so they should share one circuit and one exit; disagreement means a circuit
   switched mid-probe, a leak, or a provider is wrong. None of those is "verified".
5. **Tor confirmation is bound to the consensus IP.** It counts only when a
   Tor-authoritative provider confirmed *that same address* as Tor. A confirmation for
   a dissenting address does not vouch for the consensus address.

Provider names are unique by configuration validation, so one source cannot cast more
than one vote.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from .models import ProviderObservation


@dataclass(frozen=True, slots=True)
class ConsensusOutcome:
    """Result of evaluating one round of observations."""

    ok: bool
    ip: str | None
    candidate_ip: str | None
    tor_confirmed: bool | None
    agreeing: int
    dissenting: int
    responded: int
    error: str | None
    split: bool = False
    """Providers reported different IPs (a tie, or any dissent)."""

    @property
    def resample(self) -> bool:
        """Whether another sampling round could legitimately change the outcome.

        True for a failure caused by disagreement alone. Tor can move individual streams of
        one isolation bucket onto different circuits (for example after an exit refuses a
        destination); it then prefers the most recently used circuit, so a fresh sequential
        round normally converges on one exit. A Tor-negative result is never re-sampled.
        """
        return not self.ok and self.split and self.tor_confirmed is not False


def evaluate(
    observations: Sequence[ProviderObservation],
    *,
    quorum: int,
    require_unanimous: bool,
    require_tor_confirmation: bool,
) -> ConsensusOutcome:
    """Apply the consensus rules documented in this module."""
    successes = [o for o in observations if o.ok and o.ip is not None]
    responded = len(successes)
    if not successes:
        return ConsensusOutcome(
            ok=False,
            ip=None,
            candidate_ip=None,
            tor_confirmed=None,
            agreeing=0,
            dissenting=0,
            responded=0,
            error="no verification provider returned a valid IP",
        )

    ranked = Counter(o.ip for o in successes).most_common()
    top_ip, top_votes = ranked[0]
    tied = len(ranked) > 1 and ranked[1][1] == top_votes
    candidate = None if tied else top_ip
    agreeing = 0 if tied else top_votes
    dissenting = responded - agreeing

    negatives = [o for o in successes if o.is_tor is False]
    confirmations = [o for o in successes if o.is_tor is True and o.ip == candidate]
    tor_confirmed: bool | None
    if negatives:
        tor_confirmed = False
    elif confirmations:
        tor_confirmed = True
    else:
        tor_confirmed = None

    failures: list[str] = []
    if negatives:
        detail = ", ".join(f"{o.provider} saw {o.ip}" for o in negatives)
        failures.append(f"Tor-negative observation ({detail}): traffic is not exiting via Tor")
    if tied:
        contenders = ", ".join(f"{ip}={votes}" for ip, votes in ranked if votes == top_votes)
        failures.append(f"providers disagree with no majority ({contenders})")
    else:
        if agreeing < quorum:
            failures.append(f"IP verification quorum not met ({agreeing}/{quorum})")
        if require_unanimous and dissenting:
            dissent = ", ".join(f"{o.provider}={o.ip}" for o in successes if o.ip != candidate)
            failures.append(f"providers disagree with consensus {candidate} ({dissent})")
    if require_tor_confirmation and tor_confirmed is not True and not negatives:
        failures.append(
            "Tor route was not positively confirmed for the consensus IP"
            if candidate
            else "Tor route was not positively confirmed"
        )

    ok = not failures
    return ConsensusOutcome(
        ok=ok,
        ip=candidate if ok else None,
        candidate_ip=candidate,
        tor_confirmed=tor_confirmed,
        agreeing=agreeing,
        dissenting=dissenting,
        responded=responded,
        error="; ".join(failures) or None,
        split=len(ranked) > 1,
    )
