"""Independent exit verification: query providers through Tor, then apply consensus.

Probes run **sequentially** on purpose. They share one SOCKS isolation bucket, so the
first probe causes Tor to build (or select) a circuit and the rest reuse it. Concurrent
first requests right after ``NEWNYM`` can make Tor build several circuits at once, which
would produce exactly the disagreement that strict consensus rejects.
"""

from __future__ import annotations

import http.client
import ssl
import time
from collections.abc import Callable

from . import consensus, providers
from .config import SocksConfig, VerifyConfig
from .errors import ConfigurationError, TorRotatorError
from .models import ProviderObservation, VerificationResult
from .socks import SocksEndpoint
from .transport import HttpResponse, create_ssl_context, https_get

USER_AGENT = "tor-rotator"
"""Deliberately unversioned: a version string adds a fingerprinting bit and no value."""

Fetch = Callable[[str], HttpResponse]


class ExitVerifier:
    """Verify the current Tor exit with a multi-provider quorum."""

    def __init__(
        self,
        socks: SocksConfig,
        config: VerifyConfig,
        *,
        fetch: Fetch | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.socks = socks
        self.config = config
        self._providers = providers.resolve(config.providers, config.custom_providers)
        self._endpoint = SocksEndpoint.from_config(socks)
        self._fetch = fetch
        self._clock = clock
        self._ssl_context: ssl.SSLContext | None = None

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self._providers)

    def verify(self) -> VerificationResult:
        """Run one verification round. Never raises for network/provider failures."""
        fetch = self._fetch or self._default_fetch()
        started = self._clock()
        observations = tuple(self._probe(p, fetch) for p in self._providers)
        outcome = consensus.evaluate(
            observations,
            quorum=self.config.quorum,
            require_unanimous=self.config.require_unanimous,
            require_tor_confirmation=self.config.require_tor_confirmation,
        )
        return VerificationResult(
            ok=outcome.ok,
            ip=outcome.ip,
            tor_confirmed=outcome.tor_confirmed,
            quorum=self.config.quorum,
            agreeing=outcome.agreeing,
            dissenting=outcome.dissenting,
            responded=outcome.responded,
            candidate_ip=outcome.candidate_ip,
            observations=observations,
            duration_ms=_ms(self._clock() - started),
            error=outcome.error,
        )

    def _default_fetch(self) -> Fetch:
        if self._ssl_context is None:
            try:
                self._ssl_context = create_ssl_context(self.config.ca_file)
            except (OSError, ValueError) as exc:
                raise ConfigurationError(f"cannot load TLS trust store: {exc}") from exc
        context = self._ssl_context

        def fetch(url: str) -> HttpResponse:
            return https_get(
                url,
                endpoint=self._endpoint,
                ssl_context=context,
                timeout=self.config.timeout_seconds,
                user_agent=USER_AGENT,
            )

        return fetch

    def _probe(self, provider: providers.Provider, fetch: Fetch) -> ProviderObservation:
        started = self._clock()
        try:
            response = fetch(provider.url)
            if response.status != 200:
                raise ValueError(f"HTTP {response.status} {response.reason}".strip())
            ip, is_tor = provider.parser(response.body)
        except (TorRotatorError, OSError, http.client.HTTPException, ValueError) as exc:
            return ProviderObservation(
                provider=provider.name,
                ok=False,
                latency_ms=_ms(self._clock() - started),
                error=f"{type(exc).__name__}: {exc}",
            )
        return ProviderObservation(
            provider=provider.name,
            ok=True,
            ip=ip,
            is_tor=is_tor,
            latency_ms=_ms(self._clock() - started),
        )


ExitIpVerifier = ExitVerifier
"""Backwards-compatible alias for the 1.x class name."""


def _ms(seconds: float) -> int:
    return max(0, round(seconds * 1000))
