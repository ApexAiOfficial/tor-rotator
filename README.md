# Tor Rotator

[![CI](https://github.com/ApexAiOfficial/tor-rotator/actions/workflows/ci.yml/badge.svg)](https://github.com/ApexAiOfficial/tor-rotator/actions/workflows/ci.yml)
[![Security](https://github.com/ApexAiOfficial/tor-rotator/actions/workflows/security.yml/badge.svg)](https://github.com/ApexAiOfficial/tor-rotator/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ApexAiOfficial/tor-rotator/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ApexAiOfficial/tor-rotator)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Verified Tor circuit rotation.** Tor Rotator asks a running Tor daemon for clean circuits
(`SIGNAL NEWNYM`) over the authenticated Tor Control Protocol, confirms that Tor actually
applied the request, and then **independently verifies** the resulting exit through Tor with a
multi-provider, Tor-confirmed quorum. Control-plane success and data-plane verification are
recorded as separate facts, and neither is ever reported as the other.

It is a small, typed, dependency-free Python package and CLI, designed to run unattended
under a heavily sandboxed systemd unit.

```console
$ tor-rotator --config /etc/tor-rotator/config.toml rotate | jq '{signal_applied, verified, exit_changed, operation_succeeded}'
{
  "signal_applied": true,
  "verified": true,
  "exit_changed": true,
  "operation_succeeded": true
}
```

---

## Contents

- [Why Tor Rotator](#why-tor-rotator)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Tor setup](#tor-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [CLI examples](#cli-examples)
- [Automation](#automation)
- [Security](#security)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Development](#development)
- [License](#license)

---

## Why Tor Rotator

Most "Tor IP rotators" restart or reload the Tor daemon, or send `NEWNYM` and assume the
public IP changed. Both are wrong in ways that matter:

- **`NEWNYM` is a request, not a guarantee.** Tor rate-limits it (one application every
  10 seconds, with later requests deferred), ignores it when client functionality is
  disabled, and a fresh circuit can legitimately land on the same exit.
- **"The control command succeeded" says nothing about the route.** Only an independent
  observation through Tor's SOCKS port can show which exit is in use, and whether traffic
  exits through Tor at all.
- **One IP-echo service is a single point of failure and of trust.**

Tor Rotator models each of these facts explicitly:

| Fact | Field | Established by |
| --- | --- | --- |
| Tor accepted the request | `signal_accepted` | `250 OK` to `SIGNAL NEWNYM` |
| Tor applied it | `signal_applied` | a `650 SIGNAL NEWNYM` event received *after* the acknowledgement |
| The route is healthy and is Tor | `verified` | a quorum of HTTPS providers through Tor, with Tor confirmation bound to the consensus IP |
| The exit changed | `exit_changed` | comparing two *verified* exit IPs (`null` when either side is unverified) |
| The policy was met | `operation_succeeded` | all of the above, plus `require_exit_change` if configured |

## Features

**Control plane**
- Speaks the Tor Control Protocol directly (no controller SDK), over a loopback TCP
  `ControlPort` or a UNIX `ControlSocket`.
- **SAFECOOKIE** authentication with mutual verification: Tor must prove it knows the cookie
  before anything derived from it is sent. HASHEDPASSWORD supported, with the secret taken
  from an environment variable or a systemd credential file and never from the config file.
  NULL auth refused unless explicitly enabled.
- **Downgrade resistance:** pin the authentication method (`control.auth`) and the cookie
  path (`control.cookie_path`) so an impostor listener cannot steer authentication.
- Loopback enforced on the *resolved* addresses at connect time, not just on the hostname.
- Fail-closed protocol parsing: line and reply size caps, strict status-code rules, a proper
  QuotedString decoder (1.x used `ast.literal_eval`).

**NEWNYM confirmation**
- Distinguishes *accepted* from *applied*, and discards stale `SIGNAL` events (for example
  another controller's `NEWNYM`) that arrive before Tor acknowledges this request.
- A rate-limited `NEWNYM` is deferred by Tor, not dropped. The default 12-second
  confirmation window outlasts Tor's 10-second rate limit, so a deferred request is still
  confirmed. A confirmation that arrives immediately returns immediately.

**Exit verification**
- Multi-provider quorum (built in: `torproject`, `ipify`, `icanhazip`, `aws`, plus your own
  HTTPS endpoints), queried sequentially through one stable SOCKS isolation bucket.
- **Disagreement re-sampling:** Tor can move a single stream to another circuit (live
  testing showed it right after bootstrap), so a failure caused only by disagreement is
  re-sampled with a fresh round (`verify.max_rounds`) instead of being reported as a broken
  exit, or worse, voted away.
- **Strict consensus:** ties are never broken arbitrarily, dissent fails verification by
  default, a provider cannot vote twice, and Tor confirmation counts only for the consensus
  IP. A Tor-negative observation always fails.
- Strict response parsing (`IsTor` must be a JSON boolean). Exit addresses must be globally
  routable, and IP-only built-ins use IPv4-only hostnames to avoid false disagreements.

**Transport (standard library only)**
- Purpose-built SOCKS5 client (RFC 1928/1929): destination hostnames always go to Tor as
  domain names, so local DNS resolution cannot happen. SOCKS over TCP or a UNIX socket.
- TLS 1.2+ with certificate and hostname verification (system trust store or `ca_file`).
  No environment proxies, `.netrc`, cookies or redirects.
- A hard **total deadline** per probe (a watchdog defeats slow-drip responses) and bounded
  response sizes.

**Operations**
- `doctor`: control, bootstrap, circuit, network liveness, *and* a check that the
  configured SOCKS endpoint really is one of Tor's SOCKS listeners.
- `watch` scheduler with optional jitter, drift-free intervals, a consecutive-failure
  limit, survival of individual failures, and graceful SIGTERM/SIGINT handling.
- A single-writer `flock(2)` lock, atomic and fsynced state with counters, Prometheus
  textfile metrics, structured JSON logs on stderr, JSON results on stdout, and stable
  exit codes.

**Supply chain and hardening**
- **Zero runtime dependencies.** Fully typed (`py.typed`, `mypy --strict`).
- systemd unit rated **0.4 "SAFE"** by `systemd-analyze security` (1.0.1's unit: 3.1). In
  UNIX-socket mode it runs with `PrivateNetwork=yes`, so the service has no network access
  except Tor's sockets.
- Hash-pinned CI toolchain, SHA-pinned GitHub Actions, CodeQL, zizmor, actionlint,
  gitleaks, pip-audit, OpenSSF Scorecard, and build-provenance attestations on releases.

## Architecture

```text
             tor-rotator (CLI / library)                         Tor daemon
 ┌──────────────────────────────────────────────┐       ┌──────────────────────────┐
 │ TorRotatorService                            │       │                          │
 │   rotate():  lock → verify(before) → NEWNYM  │       │                          │
 │              → settle → verify(after) × N    │       │                          │
 │              → policy → state/metrics        │       │                          │
 │                                              │       │                          │
 │   TorControlClient ──── TCP 127.0.0.1:9051 ──┼──────►│ ControlPort/ControlSocket│
 │     PROTOCOLINFO, SAFECOOKIE, GETINFO,       │  or   │                          │
 │     SETEVENTS SIGNAL, SIGNAL NEWNYM          │ UNIX  │                          │
 │                                              │       │                          │
 │   ExitVerifier ─ SOCKS5 (domain names only) ─┼──────►│ SocksPort ──► circuit ──►│──► exit ──► HTTPS providers
 │     sequential probes, one isolation bucket  │       │                          │     (torproject, ipify, …)
 │     → consensus.evaluate()                   │       └──────────────────────────┘
 └──────────────────────────────────────────────┘
```

Tor Rotator deliberately does **not** own the Tor daemon's lifecycle. Installing and
configuring Tor, firewalling, and restarts remain deployment responsibilities. It never
shells out, never reloads Tor, and never edits torrc.

**Consensus rules** (in `tor_rotator/consensus.py`, a pure function):

1. Any Tor-negative observation (`IsTor: false`) fails verification: traffic is leaving
   through a non-Tor path.
2. The consensus IP needs strictly more votes than any other IP; a tie is no consensus.
3. At least `quorum` providers must report the consensus IP.
4. With `require_unanimous` (default), any responding provider that reports a different IP
   fails verification.
5. With `require_tor_confirmation` (default), a Tor-authoritative provider must confirm
   *the consensus IP itself* as a Tor exit.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the state machine, module map and
design decisions, and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for trust boundaries.

## Requirements

- Linux (uses `flock(2)` and UNIX-domain sockets; other POSIX systems are untested).
- Python 3.11, 3.12, 3.13 or 3.14.
- A running Tor client from your distribution or the Tor Project's repositories. The live
  suite has been run against Tor 0.4.9.15 (Debian 13); the weekly CI live job uses Ubuntu
  24.04's packaged Tor. Tor Rotator does not install or manage Tor.
- A CA trust store (`ca-certificates` on Debian/Ubuntu), or `verify.ca_file`.

## Installation

Tor Rotator has no runtime dependencies, so installing it pulls in nothing else.

**Into a dedicated virtual environment (recommended for services):**

```bash
sudo python3 -m venv /opt/tor-rotator/venv
sudo /opt/tor-rotator/venv/bin/pip install "git+https://github.com/ApexAiOfficial/tor-rotator@v2.0.0"
/opt/tor-rotator/venv/bin/tor-rotator --version
```

**From a release wheel, with provenance verification:**

```bash
gh release download v2.0.0 --repo ApexAiOfficial/tor-rotator --pattern '*.whl' --pattern 'SHA256SUMS'
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify tor_rotator-2.0.0-py3-none-any.whl --repo ApexAiOfficial/tor-rotator
sudo /opt/tor-rotator/venv/bin/pip install ./tor_rotator-2.0.0-py3-none-any.whl
```

**For interactive use:** `pipx install git+https://github.com/ApexAiOfficial/tor-rotator`.

**From a checkout:** `python3 -m pip install .`

## Tor setup

### Debian and Ubuntu: no torrc changes

The Debian `tor` package already exposes a control socket (`/run/tor/control`), a SOCKS
socket (`/run/tor/socks`) and group-readable SAFECOOKIE authentication. Give the account
that runs Tor Rotator membership of the `debian-tor` group and use
[`deploy/config.debian.toml`](deploy/config.debian.toml):

```bash
sudo usermod -aG debian-tor "$USER"          # interactive use (log in again afterwards)
sudo install -d -m 0750 /etc/tor-rotator
sudo install -m 0640 deploy/config.debian.toml /etc/tor-rotator/config.toml
tor-rotator --config /etc/tor-rotator/config.toml --pretty doctor
```

### Other distributions

Merge [`deploy/tor/torrc.d-rotator.conf`](deploy/tor/torrc.d-rotator.conf) into your torrc.
It enables a UNIX `ControlSocket` (or a loopback `ControlPort`), SAFECOOKIE authentication
readable only by Tor's group, and `SafeSocks`. Then run `tor --verify-config` and restart Tor
as a deployment step.

Do **not** declare a second `SocksPort` on an address/port that is already bound: Tor
refuses to start. You do not need to add `IsolateSOCKSAuth`, because Tor enables it by
default on SOCKS listeners. It is what keeps verification probes on their own circuits.

## Configuration

Configuration is a TOML file passed with `--config`, or via `$TOR_ROTATOR_CONFIG`. With
neither, built-in defaults apply. [`config.example.toml`](config.example.toml) documents
every key. Loading is strict:

- Unknown sections and keys, wrongly-typed values (`port = "9051"`, `port = true`) and
  non-finite numbers are rejected, as are semantically unsafe settings (see below).
- World-writable config files and files over 1 MiB are refused.
- Secrets are never read from the config file: keys named `password`, `control_password`
  or `cookie` are rejected outright.

| Key | Default | Description |
| --- | --- | --- |
| **`[control]`** | | |
| `mode` | `"tcp"` | `"tcp"` (loopback ControlPort) or `"unix"` (ControlSocket). |
| `host` | `"127.0.0.1"` | TCP only. Must be loopback; resolved addresses are re-checked at connect time. |
| `port` | `9051` | TCP only. |
| `socket_path` | `"/run/tor/control"` | UNIX only. Absolute path. |
| `auth` | `"auto"` | `auto`, `safecookie`, `hashedpassword` or `null`. Pinning prevents authentication downgrades. |
| `cookie_path` | unset | Pin the cookie file Tor must advertise for SAFECOOKIE. |
| `password_env` | unset | Environment variable holding the HASHEDPASSWORD secret. |
| `password_file` | unset | File holding the secret (absolute, or `${CREDENTIALS_DIRECTORY}/name` for systemd `LoadCredential=`). Must not be accessible to other users. |
| `allow_null_auth` | `false` | Permit unauthenticated control access (not recommended). |
| `connect_timeout_seconds` | `5.0` | Control connection and reply timeout, in (0, 60]. |
| `signal_event_timeout_seconds` | `12.0` | Wait for Tor to confirm applying NEWNYM, in (0, 120]. Keep it above 10 s. |
| **`[socks]`** | | |
| `mode` | `"tcp"` | `"tcp"` or `"unix"`. |
| `host` / `port` | `"127.0.0.1"` / `9050` | TCP SOCKS listener. Must be loopback unless `allow_non_loopback`. |
| `socket_path` | `"/run/tor/socks"` | UNIX SOCKS socket. |
| `probe_username` / `probe_password` | `"tor-rotator-probe"` / `"fixed-probe-isolation"` | Stable isolation credentials (1–255 bytes). These are labels, not secrets. |
| `allow_non_loopback` | `false` | Allow a remote SOCKS host, e.g. a Tor sidecar on a private network. |
| **`[verify]`** | | |
| `quorum` | `2` | Providers that must agree on the exit IP (≤ number of providers). |
| `require_unanimous` | `true` | Fail if any responding provider disagrees. |
| `require_tor_confirmation` | `true` | Require Tor confirmation of the consensus IP (needs `torproject` in `providers`). |
| `timeout_seconds` | `15.0` | Total deadline per probe, in (0, 120]. |
| `attempts_after_rotation` | `4` | Post-rotation verification attempts, 1–20. |
| `retry_delay_seconds` | `2.0` | Delay between attempts, in [0, 300]. |
| `max_rounds` | `3` | Sampling rounds per verification when providers *disagree* (1–10). Never applied to Tor-negative results. |
| `providers` | `["torproject", "ipify", "icanhazip"]` | Unique names of built-in or custom providers. |
| `ca_file` | unset | PEM CA bundle to use instead of the system trust store. |
| `[verify.custom_providers.<name>]` | — | `url` (HTTPS, no credentials or fragment), `format` (`"text"`/`"json"`), `json_field` (JSON only; dots address nesting). |
| **`[rotation]`** | | |
| `interval_seconds` | `600.0` | `watch` interval, 10 s to 7 days, measured start to start. |
| `jitter_seconds` | `0.0` | Uniform random extra delay per cycle, in [0, interval). |
| `settle_seconds` | `1.0` | Pause after a confirmed NEWNYM before verifying, in [0, 60]. |
| `require_exit_change` | `false` | Succeed only on a verified change of exit IP. |
| `max_consecutive_failures` | `0` | `watch` exits with status 1 after this many failures in a row (0 = never). |
| **`[runtime]`** | | |
| `state_file` | `"/var/lib/tor-rotator/state.json"` | Persisted state (mode 0640, atomic writes). |
| `lock_file` | `"/var/lib/tor-rotator/rotate.lock"` | Single-writer rotation lock. |
| `metrics_file` | unset | Prometheus textfile-collector output (mode 0644). |
| `log_format` | `"json"` | `"json"` or `"text"` (stderr). |
| `log_level` | `"INFO"` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |

Environment variables: `TOR_ROTATOR_CONFIG` (config path), the variable named by
`control.password_env`, and `CREDENTIALS_DIRECTORY` (set by systemd for `LoadCredential=`).

`tor-rotator config` validates a configuration and prints the effective settings
(`probe_password` redacted; secrets are never part of the config object at all).

## Usage

```text
tor-rotator [-c CONFIG] [--pretty] [--log-level LEVEL] COMMAND

  doctor    check control plane, bootstrap, SOCKS wiring and the Tor exit
  verify    verify the current Tor exit without rotating
  rotate    request NEWNYM and verify the resulting exit
  status    show the persisted rotation state
  watch     rotate on the configured schedule until stopped (--once: one iteration)
  config    validate configuration and print the effective settings
  metrics   print Prometheus metrics derived from persisted state
```

Results go to **stdout** as JSON (`--pretty` to indent). Logs go to **stderr** (JSON by
default), so piping into `jq` never mixes the two. Errors that prevent a result are written
to stderr as `{"ok": false, "error": ..., "error_type": ..., "exit_code": ...}`.

| Exit code | Meaning |
| --- | --- |
| `0` | Success: the operation met its configured policy. |
| `1` | The operation ran but did not succeed (the JSON result says why). For `status`: nothing recorded yet. |
| `2` | Invalid command-line usage. |
| `3` | Configuration error. |
| `4` | Runtime error: no result could be produced (e.g. unreadable state). |
| `5` | Another rotation holds the lock; nothing was changed. |
| `130` | Interrupted. |

## CLI examples

```bash
# Health of everything, human-readable
tor-rotator -c /etc/tor-rotator/config.toml --pretty doctor

# Just the failing checks
tor-rotator -c /etc/tor-rotator/config.toml doctor | jq '.checks[] | select(.ok | not)'

# Current exit, without touching circuits
tor-rotator -c /etc/tor-rotator/config.toml verify | jq -r 'if .ok then .ip else "UNVERIFIED: \(.error)" end'

# Rotate, then show the before/after verified exits
tor-rotator -c /etc/tor-rotator/config.toml rotate | jq '{before: .before.ip, after: .after.ip, exit_changed, error}'

# Insist on a different exit (retries verification up to verify.attempts_after_rotation)
TOR_ROTATOR_CONFIG=./strict.toml tor-rotator rotate     # with rotation.require_exit_change = true

# Counters and the last rotation
tor-rotator -c /etc/tor-rotator/config.toml status | jq '{counters, consecutive_failures, last_success_at}'

# Validate a config before deploying it
tor-rotator -c ./candidate.toml config >/dev/null && echo "config OK"

# One scheduled iteration with debug logs
tor-rotator -c /etc/tor-rotator/config.toml --log-level DEBUG watch --once
```

A `doctor` report (abridged):

```json
{
  "healthy": true,
  "checks": [
    {"name": "control", "ok": true, "detail": "Tor 0.4.9.15"},
    {"name": "bootstrap", "ok": true, "detail": "100%"},
    {"name": "circuit_established", "ok": true, "detail": "Tor reports a usable circuit"},
    {"name": "network_liveness", "ok": true, "detail": "Tor reports the network up"},
    {"name": "socks_listener", "ok": true, "detail": "configured unix:/run/tor/socks is a Tor SOCKS listener"},
    {"name": "exit", "ok": true, "detail": "verified Tor exit 185.220.101.1"}
  ]
}
```

A rotation where Tor applied `NEWNYM` but the new circuit uses the same exit is
**legitimate**: `operation_succeeded: true`, `exit_changed: false`. Set
`rotation.require_exit_change = true` only if your application genuinely needs a verified IP
difference; the rotation then fails honestly rather than pretending Tor guarantees one.

## Automation

### systemd service (recommended)

[`deploy/systemd/tor-rotator.service`](deploy/systemd/tor-rotator.service) runs `watch`
under a dedicated account with an empty capability set, a read-only filesystem, a system
call filter and, in UNIX-socket mode, **no network namespace access at all**
(`PrivateNetwork=yes`).

```bash
sudo install -m 0644 deploy/sysusers/tor-rotator.conf /etc/sysusers.d/ && sudo systemd-sysusers
sudo install -d -m 0750 -g tor-rotator /etc/tor-rotator
sudo install -m 0640 -g tor-rotator deploy/config.debian.toml /etc/tor-rotator/config.toml
sudo install -m 0644 deploy/systemd/tor-rotator.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tor-rotator.service
journalctl -u tor-rotator -f
systemd-analyze security tor-rotator.service      # expect ~0.4 SAFE
```

For TCP control/SOCKS on loopback, add [`tcp-loopback.conf`](deploy/systemd/tcp-loopback.conf)
as a drop-in: it re-enables only `AF_INET`/`AF_INET6` and limits IP traffic to
`localhost`. For HASHEDPASSWORD, prefer systemd credentials over environment variables:

```ini
# /etc/systemd/system/tor-rotator.service.d/password.conf
[Service]
LoadCredential=tor-control-password:/etc/tor-rotator/control-password
```

with `password_file = "${CREDENTIALS_DIRECTORY}/tor-control-password"` in the config.

### systemd timer

Prefer discrete runs? Use [`tor-rotator-rotate.service`](deploy/systemd/tor-rotator-rotate.service)
with [`tor-rotator-rotate.timer`](deploy/systemd/tor-rotator-rotate.timer) (every 10 min,
60 s randomised delay) instead of the long-running service. Exit status 5 (lock held) is
treated as success.

### cron

```cron
*/15 * * * * tor-rotator -c /etc/tor-rotator/config.toml rotate >/dev/null 2>>/var/log/tor-rotator.log || [ $? -eq 5 ]
```

### Monitoring

Set `runtime.metrics_file` to a node_exporter textfile-collector path (or run
`tor-rotator metrics`). Exported series include `tor_rotator_rotations_total{outcome}`,
`tor_rotator_exit_changes_total`, `tor_rotator_consecutive_failures`,
`tor_rotator_last_success_timestamp_seconds`, `tor_rotator_last_rotation_success`,
`tor_rotator_exit_verified` and `tor_rotator_build_info`. Exit IP addresses are never
exported. Example alerts:

```yaml
- alert: TorRotatorFailing
  expr: tor_rotator_consecutive_failures >= 3
  for: 5m
- alert: TorRotatorStale
  expr: time() - tor_rotator_last_success_timestamp_seconds > 3600
```

### Python API

```python
from tor_rotator import AppConfig, TorRotatorService

service = TorRotatorService(AppConfig.load("/etc/tor-rotator/config.toml"))
result = service.rotate()          # raises LockBusyError if another rotation is running
if result.operation_succeeded:
    print("now exiting via", result.after.ip)
else:
    print("rotation failed:", result.error)
```

`VerificationResult.ip` is populated only when verification succeeded, so code that forgets
to check `.ok` still cannot act on an unverified address.

### Containers

Run Tor in its own container and share its UNIX sockets through a volume (preferred), or
point `[socks]` at the Tor container's SOCKS port with `allow_non_loopback = true`. The
control connection is loopback/UNIX-only by design; share the control socket rather than
exposing a ControlPort on a network.

## Security

Defaults are chosen to fail closed. Key properties:

- The control connection is loopback-only or a UNIX socket, authenticated, and SAFECOOKIE
  is mutually verified. Authentication method and cookie path can be pinned.
- No secrets in configuration files. Passwords come from the environment or a credential
  file that other users cannot read.
- All verification traffic goes through Tor with remote DNS by construction, over verified
  TLS, with hard deadlines and bounded responses.
- No shell invocation, no Tor reload or restart, no torrc mutation, no package installation
  at runtime.
- State and lock files use `O_NOFOLLOW` and atomic replacement.
- Zero runtime dependencies; the CI toolchain is hash-pinned and audited.

Read [SECURITY.md](SECURITY.md) to **report a vulnerability** (privately, through GitHub
Security Advisories), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for trust boundaries
and residual risks.

## Limitations

- **Not a VPN or transparent proxy.** It controls circuits for applications that already use
  Tor's SOCKS listener. It does not route the rest of the host's traffic.
- **Not anonymity in a box.** Applications can still identify you through logins, cookies,
  fingerprinting, WebRTC or by bypassing the proxy. Use Tor Browser for anonymous browsing.
- **`NEWNYM` does not promise a new IP.** A new circuit can reuse an exit; Tor rate-limits
  `NEWNYM` to one application every 10 seconds.
- **`NEWNYM` is global.** It affects every client of that Tor instance, not just one
  application.
- **Third-party observers.** Providers see requests from Tor exit addresses (never your own
  address) and their timing. Tor confirmation depends on `check.torproject.org`. Use
  `[verify.custom_providers]` to rely on endpoints you operate.
- **Provider availability.** Some services rate-limit or challenge Tor exits; the quorum
  tolerates individual failures, and you can choose other providers.
- **Linux only** (tested). It does not attempt country selection, relay selection or
  hand-built circuits, and it does not manage the Tor daemon.

## Troubleshooting

Start with `tor-rotator --pretty doctor` and `tor-rotator config`; add `--log-level DEBUG`
for detail.

| Symptom | Likely cause and fix |
| --- | --- |
| `cannot connect to Tor ControlPort at 127.0.0.1:9051` | No ControlPort configured. On Debian/Ubuntu use `mode = "unix"` (see `deploy/config.debian.toml`); elsewhere enable one with `deploy/tor/torrc.d-rotator.conf`. |
| `cannot connect to Tor control socket … Permission denied` / `cannot open Tor SAFECOOKIE file` | The account is not in Tor's group (`debian-tor` on Debian). Add it and start a new login session, or set `SupplementaryGroups=` in systemd. |
| `Tor only offered deprecated COOKIE auth` | Enable `CookieAuthentication 1`; modern Tor offers SAFECOOKIE alongside it. |
| `Tor requires HASHEDPASSWORD auth but no password is configured` | Set `password_env` or `password_file`, or switch Tor to cookie authentication. |
| `does not match the pinned control.cookie_path` | Tor advertised a different cookie file. Fix the pin, or investigate what is listening on the control port. |
| `did not confirm applying it within 12s` | Another controller sent `NEWNYM` at the same time, or Tor has client functionality disabled. Retry; raise `signal_event_timeout_seconds` if needed. |
| `providers disagree with consensus …` | Disagreement persisted across `verify.max_rounds` sampling rounds: a provider is wrong, or an exit keeps refusing one provider's address. Re-run. If it persists, investigate the provider or raise `max_rounds`; `require_unanimous = false` relaxes to majority voting. |
| `Tor-negative observation … traffic is not exiting via Tor` | **The SOCKS endpoint is not routing through Tor.** Check `[socks]` and the `socks_listener` doctor check before anything else. |
| `configured … is not a Tor SOCKS listener` | `[socks]` points at the wrong port or socket; compare with the listeners Tor reports. |
| `CERTIFICATE_VERIFY_FAILED` | No CA trust store. Install `ca-certificates`, or set `verify.ca_file`. |
| `probe exceeded its 15s deadline` | Slow circuits or network. Raise `verify.timeout_seconds`, and check `doctor` for bootstrap/liveness. |
| `HTTP 403`/`HTTP 429` from a provider | The provider is blocking or rate-limiting Tor exits. Use other built-ins or a custom provider. |
| Exit code `5` | Another rotation is in progress (e.g. `watch` and a manual `rotate`). Nothing was changed. |
| `refusing world-writable config file` | `chmod o-w` the config (0640 recommended). |
| `state file … is corrupt` | Inspect or remove the state file. Rotation itself recovers automatically, resets the counters and reports a warning. |

More operational guidance: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Testing

```bash
python -m pytest                      # unit + protocol + integration suite, no network needed
python -m pytest --cov                # with branch coverage (gate: 95%)
scripts/live-tor.sh                   # live tests against a private, throwaway Tor client
scripts/live-tor-docker.sh            # the same, inside a disposable Debian container
```

- **Protocol-level fakes, not mocks.** The suite runs a fake Tor control port (real
  SAFECOOKIE handshake, implemented independently of the production code), a fake SOCKS5
  proxy, and TLS IP-echo servers with test-CA certificates. The production socket, TLS and
  timeout paths run unmodified.
- **Property-based tests** (Hypothesis) assert consensus invariants and QuotedString
  round-trips; dedicated regression tests pin every 1.0.1 defect.
- **Live tests** cover TCP and UNIX control and SOCKS, SAFECOOKIE and HASHEDPASSWORD,
  deferred-`NEWNYM` confirmation, real exit changes, and the CLI end to end.
- CI runs the suite on Python 3.11 to 3.14; the live suite runs weekly and on demand.

Details: [docs/TESTING.md](docs/TESTING.md).

## Development

```bash
git clone https://github.com/ApexAiOfficial/tor-rotator && cd tor-rotator
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements/dev.txt     # hash-pinned toolchain
pip install --no-deps --no-build-isolation -e .
pre-commit install                                       # optional
scripts/check.sh                                         # every CI gate, locally
```

`scripts/check.sh` is exactly what CI runs: ruff (lint and format), `mypy --strict`, pytest
with the coverage gate, release-metadata consistency, sdist/wheel build, `twine check`,
wheel-content checks, a clean-venv install smoke test, pip-audit, actionlint and zizmor.
Run a single stage with `scripts/check.sh lint|types|test|package|security`.

```text
src/tor_rotator/
  cli.py          argument parsing, JSON output, exit codes, signal handling
  config.py       typed TOML loading and safety validation
  control.py      Tor Control Protocol client (auth, GETINFO, NEWNYM confirmation)
  socks.py        SOCKS5 client, remote DNS by construction
  transport.py    HTTPS over SOCKS with a total deadline and size limits
  providers.py    built-in and custom IP-echo providers, strict parsing
  consensus.py    the consensus rules (pure function)
  verify.py       exit verification orchestration
  service.py      health checks, rotation state machine, scheduler
  state.py        atomic persisted state and counters
  metrics.py      Prometheus text rendering
  lock.py, log.py, models.py, errors.py
deploy/           systemd units, sysusers, torrc snippet, Debian config
scripts/          check.sh, live-tor*.sh, lock.sh, check_release.py
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); releases follow
[docs/RELEASING.md](docs/RELEASING.md); changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © ApexAi Official.

Tor Rotator is an independent project. It is not affiliated with or endorsed by The Tor
Project. "Tor" is a trademark of The Tor Project, Inc.
