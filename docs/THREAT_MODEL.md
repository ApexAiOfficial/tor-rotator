# Threat Model

## Assets

1. **The integrity of verification results**: automation acts on `verified`,
   `operation_succeeded` and `after.ip`.
2. **Control-plane authority**: whoever can authenticate to Tor's control interface can
   reconfigure Tor.
3. **Control credentials**: the SAFECOOKIE cookie, or the HASHEDPASSWORD secret.
4. **Routing integrity**: verification traffic, and the applications relying on Tor, must
   exit through Tor.

## Trust boundaries

```text
 [operator/config] ─► tor-rotator ─(UNIX socket or loopback TCP)─► Tor control
                          │
                          └─(SOCKS5, UNIX or loopback)─► Tor ─► Tor network ─► exit ─► HTTPS providers
```

| Component | Trust |
| --- | --- |
| Config file | Trusted, but must not be world-writable (checked). |
| Tor daemon | Trusted for control. Its identity is verified with SAFECOOKIE when available. |
| Local listeners on the control port | **Untrusted until authenticated**: an unprivileged process could bind the port while Tor is down. |
| Tor exit relays | Untrusted. They can see and alter plaintext, which is why every probe uses verified TLS. |
| IP-echo providers | Partially trusted individually. Trust comes from a quorum plus Tor-authoritative confirmation. |
| Network between exit and provider | Untrusted. TLS with hostname verification. |

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| T1 | Impostor control listener (port squatting while Tor is down) captures credentials | SAFECOOKIE is mutually authenticated: the server must prove cookie knowledge first. `control.auth` pinning prevents a downgrade to HASHEDPASSWORD; `cookie_path` pinning prevents redirection to another file. UNIX sockets use filesystem permissions. | With `auth = "auto"` and a password configured, an impostor that offers only HASHEDPASSWORD receives the password. Pin `auth`, or use UNIX sockets. |
| T2 | Control port exposed to the network | Non-loopback hosts rejected in config and again after DNS resolution. | Misconfigured Tor itself (e.g. `ControlPort 0.0.0.0:9051`) is outside this tool's control. |
| T3 | Verification traffic leaks outside Tor (DNS or direct) | Hostnames only ever sent to the SOCKS proxy; no local resolution; no env proxies; systemd `PrivateNetwork=yes` (UNIX mode) or IP allow-list to localhost (TCP mode). | None known within the process. |
| T4 | SOCKS endpoint is not actually Tor (misconfiguration or a malicious proxy) | `doctor` cross-checks the endpoint against Tor's `net/listeners/socks`; a Tor-negative observation is fatal; Tor confirmation of the consensus IP is required by default. | A malicious proxy that *also* forwards through Tor would pass; this is out of scope (local attacker with listener control). |
| T5 | One lying or compromised provider | Quorum, strict unanimity, one vote per provider, Tor confirmation bound to the consensus IP. | Collusion of a quorum of providers *and* the Tor authority; mitigate with custom providers you operate. |
| T6 | Malicious exit tampers with responses | TLS 1.2+ with certificate and hostname verification; no redirects. | A CA compromise (general web-PKI risk). Pin a private CA via `verify.ca_file` with custom providers if required. |
| T7 | Resource exhaustion by a hostile peer (huge or slow responses) | Total probe deadline (watchdog), body size caps, control line/reply caps, bounded config/state/secret file sizes, JSON depth errors handled. | — |
| T8 | Stale or foreign NEWNYM events mistaken for confirmation | Only events after this request's `250 OK` count. | Another controller's NEWNYM applied *after* our acknowledgement is indistinguishable from ours. Either way, circuits were cleaned after our request. |
| T9 | Local file attacks (symlinks, races, world-writable config) | `O_NOFOLLOW` on state, lock, cookie and password files; regular-file checks; atomic replace; world-writable config refused; restrictive modes (0640/0600). | An attacker who controls the service account or root. |
| T10 | Secret disclosure via config, logs or output | Secrets rejected in TOML; passwords hex-encoded on the wire, never logged; `config` output redacts `probe_password`; metrics contain no IPs. | Environment variables are visible to the same user via `/proc`; prefer `password_file` with `LoadCredential=`. |
| T11 | Supply-chain compromise | Zero runtime dependencies; hash-pinned toolchain; SHA-pinned actions; CodeQL, zizmor, gitleaks, pip-audit; provenance attestations. | Compromise of Python itself or of the build platform. |
| T12 | Concurrent rotations corrupt state | `flock(2)` single writer; atomic writes. | — |

## Privacy notes

- Logs, state and the JSON output contain **Tor exit** IP addresses (public relay
  addresses), never the host's own address, provided the SOCKS endpoint is Tor. The
  Tor-negative rule makes the non-Tor case fail loudly.
- Providers observe probe requests from exit relays and their timing. The `User-Agent` is the
  unversioned constant `tor-rotator`, to avoid adding fingerprinting bits.
- `NEWNYM` affects every client of the Tor instance. Rotation timing correlates across
  applications sharing that instance; jitter reduces the predictability of the schedule.
