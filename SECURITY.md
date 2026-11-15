# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | Yes |
| 1.x | No. Upgrade to 2.x; 1.0.1 has a known exit-verification defect (see CHANGELOG). |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/ApexAiOfficial/tor-rotator/security/advisories/new)
("Security" tab → "Report a vulnerability"). Include affected versions, a description of the
impact, and reproduction steps or a proof of concept if you have one.

What to expect:

- An acknowledgement within **3 business days**.
- An initial assessment within **10 business days**.
- Coordinated disclosure: we agree on a timeline with you, publish a fix and a GitHub
  Security Advisory, and credit you unless you prefer otherwise.

Reports about Tor itself belong with [The Tor Project](https://support.torproject.org/misc/bug-or-feedback/).

## Scope

In scope: this repository's code, packaging, CI workflows and deployment examples. For
example: authentication bypass or downgrade on the control connection, traffic that escapes
Tor (DNS or direct connections), a verification result that reports success when it should
not, unsafe file handling, or secrets leaking into logs, state or output.

Out of scope: limitations documented in the README (for instance, that `NEWNYM` does not
guarantee a new IP), vulnerabilities in Tor or third-party IP-echo services, and issues that
require an attacker who already controls the service account or root.

## Security properties

- **Control plane:** loopback-only TCP (enforced on resolved addresses) or a UNIX socket.
  SAFECOOKIE with mutual verification, preferred automatically. Optional pinning of the
  authentication method and cookie path for downgrade resistance. NULL authentication is
  refused unless explicitly enabled.
- **Secrets:** never accepted in TOML. The HASHEDPASSWORD secret comes from an environment
  variable or a credential file inaccessible to other users (systemd `LoadCredential=`
  supported). It is sent hex-encoded and is never logged or echoed.
- **Data plane:** every verification request goes through Tor's SOCKS listener with the
  hostname sent to Tor (no local DNS), over TLS 1.2+ with certificate and hostname
  verification, without environment proxies, `.netrc`, cookies or redirects, under a hard
  total deadline with bounded response sizes.
- **Verification integrity:** strict quorum, unanimity by default, no arbitrary
  tie-breaking, one vote per provider, Tor confirmation bound to the consensus IP, and
  Tor-negative observations are fatal.
- **Local files:** the config file must not be world-writable. State, lock and cookie files
  are opened with `O_NOFOLLOW`. State is written atomically (mode 0640) and metrics contain
  no IP addresses.
- **Process:** no shell invocation, no Tor reload or restart, no torrc mutation, no runtime
  package installation. The systemd units run with no capabilities and a system-call
  filter, and in UNIX-socket mode with no network namespace access (`PrivateNetwork=yes`).
- **Supply chain:** zero runtime dependencies, hash-pinned CI toolchain, SHA-pinned GitHub
  Actions, automated dependency, workflow and secret scanning, and build-provenance
  attestations for release artifacts.

## Deployment checklist

1. Install Tor from your distribution or the Tor Project's signed repositories and keep it
   updated.
2. Make sure the control interface is a UNIX socket or a loopback-only port, and that only
   Tor's group can read the auth cookie.
3. Run Tor Rotator as a dedicated, unprivileged account (see `deploy/sysusers`).
4. Prefer `control.auth = "safecookie"` plus `control.cookie_path` pinning.
5. Use the hardened unit and confirm `systemd-analyze security tor-rotator.service` on the
   target host.
6. Decide on retention for state, logs and metrics according to your privacy requirements.
   Logs and state contain Tor *exit* IP addresses, never your own address.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model.
