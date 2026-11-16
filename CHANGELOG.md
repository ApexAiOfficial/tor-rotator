# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-15

A security- and correctness-focused rebuild. Configuration files from 1.x remain valid
unless they relied on behaviour that was unsafe (see *Breaking changes*).

### Fixed

- **Exit-IP consensus verification.** Tor confirmation was computed across *all*
  observations instead of being bound to the consensus IP. If check.torproject.org saw
  IP A while two other providers agreed on IP B, 1.0.1 reported `ok=true, ip=B,
  tor_confirmed=true`, although B was never confirmed as a Tor exit. Confirmation now counts
  only when a Tor-authoritative provider confirmed the consensus IP itself.
- Ties between IPs were resolved arbitrarily (whichever `Counter.most_common` returned
  first). A tie now means "no consensus".
- A provider listed twice in `verify.providers` could satisfy a multi-provider quorum on its
  own. Duplicates are now rejected.
- `IsTor` was coerced with `bool()`, so the string `"false"` counted as Tor-positive. Provider
  responses are now parsed strictly.
- `exit_changed` and `rotation.require_exit_change` compared IPs even when one side had failed
  verification. With `require_exit_change`, an unverified pre-rotation exit led to `None ==
  ip` → "no error" → a reported success. Only verified addresses are compared now, and a
  change that cannot be proven fails the policy.
- A `650 SIGNAL NEWNYM` event received *before* Tor acknowledged this request (for example
  from another controller) was accepted as confirmation. Such stale events are now discarded.
- A rate-limited NEWNYM, which Tor defers rather than drops, was reported as not applied
  because the 2 s confirmation window was shorter than Tor's 10 s rate-limit window. The
  default is now 12 s.
- Wrongly-typed config values (`port = "9051"`, `port = true`, `nan`) crashed with a
  traceback or were silently accepted. A corrupt state file also crashed with a traceback.
  Both are now controlled errors.
- In `watch` mode, one lock collision or state-write error ended the daemon. Failures are now
  logged and survived.
- PROTOCOLINFO quoted strings were decoded with `ast.literal_eval` (Python, not Tor, escape
  rules). They now use a dedicated Tor QuotedString decoder.
- Documentation claimed `IsolateSOCKSAuth` had to be added to the SocksPort; Tor enables it by
  default.

### Added

- Zero runtime dependencies: a standard-library SOCKS5 client (domain-name addressing only,
  so DNS is always resolved by Tor) and HTTPS transport replace `requests` and the
  unmaintained `PySocks`.
- SOCKS over a UNIX socket (`socks.mode = "unix"`), enabling a `PrivateNetwork=yes` systemd
  sandbox.
- A total per-probe deadline (watchdog) and bounded response sizes.
- Disagreement re-sampling (`verify.max_rounds`, default 3). Live testing showed Tor moving
  individual probe streams of one isolation bucket onto different circuits; a fresh round
  converges instead of a false failure. Results report `rounds`.
- Strict consensus option `verify.require_unanimous` (default on), a Tor-negative-is-fatal
  rule, globally-routable exit validation, IPv4-only built-in endpoints, the `aws` provider,
  and user-defined `[verify.custom_providers]`.
- Control hardening: `control.auth` method pinning (downgrade resistance),
  `control.cookie_path` pinning, loopback enforcement on resolved addresses, systemd
  credential support via `control.password_file`, and reply size limits.
- `doctor` health checks for bootstrap progress, circuit establishment, network liveness,
  and whether the configured SOCKS endpoint is one of Tor's SOCKS listeners.
- `watch`: jitter, drift-free scheduling, `max_consecutive_failures`, graceful SIGTERM/SIGINT.
- State schema 2 with counters and failure streaks (1.x state is read transparently),
  Prometheus textfile metrics (`runtime.metrics_file`, `tor-rotator metrics`), and the
  `config` command.
- `$TOR_ROTATOR_CONFIG`, `--log-level`, `--version`, `python -m tor_rotator`.
- Hardened systemd units (exposure 0.4 "SAFE", previously 3.1), a timer variant, a TCP
  drop-in, sysusers configuration, and a Debian profile that needs no torrc changes.
- Test suite rebuilt around protocol-level fakes, with property-based tests, branch coverage
  gate at 95%, and opt-in live tests against a real Tor client.
- CI on Python 3.11–3.14, CodeQL, zizmor, actionlint, gitleaks, pip-audit, OpenSSF Scorecard,
  hash-pinned toolchain, SHA-pinned actions, and attested release artifacts.

### Hardening from independent review

An independent multi-pass review (security, correctness, integration, failure modes)
before publication led to these changes:

- The probe watchdog also covers the SOCKS negotiation and the TLS handshake. Control-protocol
  replies get a total deadline (a trickling listener can no longer hold a reply open).
- Truncated HTTP bodies are rejected. A configured CA file must be a regular file that is not
  world-writable.
- A Tor-negative verdict survives an unusual address field; only Tor-authoritative providers
  may vouch for or against Tor.
- Controlled verifier errors during a rotation are recorded and persisted as failures instead
  of escaping. A stop request cancels verification between probes, and the systemd unit
  allows 90 s to stop.
- doctor's SOCKS-listener check no longer equates `127.0.0.1` with `[::1]` (only `localhost`
  matches either). Bracketed IPv6 hosts connect correctly.
- `--help` documents exit code 130. The Debian quick start, metrics under the hardened unit
  (`deploy/systemd/metrics.conf`) and `max_consecutive_failures` semantics are documented
  accurately.

### Breaking changes

- Distinct exit codes: `3` configuration error, `4` runtime error, `5` rotation lock held
  (all were `2` in 1.x; `2` now means command-line usage error only).
- `VerificationResult.ip` is populated only when verification succeeded. The plurality
  address is still available as `candidate_ip`.
- Configurations with duplicate or unknown providers, a quorum that cannot be met, a
  non-loopback SOCKS host, or `require_tor_confirmation` without a Tor-authoritative provider
  are rejected at load time.
- `ControlStatus.newnym_wait_seconds` (always `null` in 1.x) was removed.
- The `requests`-based `ExitIpVerifier(request_get=...)` hook is replaced by
  `ExitVerifier(fetch=...)`. `ExitIpVerifier` remains as an alias.

## [1.0.1] - 2026-08-31

- Fix NEWNYM success-path latency: a confirmed `650 SIGNAL NEWNYM` event now reaches the
  waiter immediately instead of waiting out `control.signal_event_timeout_seconds`.
- Make the test suite hermetic: rotation tests use a test-local lock file.
- Fix CI lint scope, and Tor deployment docs for Ubuntu 24.04/Debian.

## [1.0.0] - 2026-08-29

- Initial implementation: authenticated Tor ControlPort/ControlSocket backend, NEWNYM
  acknowledgement versus application via SIGNAL events, multi-provider SOCKS5h exit
  verification with quorum and Tor-route confirmation, atomic state, rotation locking, JSON
  logging, CLI, systemd and torrc examples.

[2.0.0]: https://github.com/ApexAiOfficial/tor-rotator/releases/tag/v2.0.0
[1.0.1]: https://github.com/ApexAiOfficial/tor-rotator/blob/main/CHANGELOG.md#101---2026-08-31
[1.0.0]: https://github.com/ApexAiOfficial/tor-rotator/blob/main/CHANGELOG.md#100---2026-08-29
