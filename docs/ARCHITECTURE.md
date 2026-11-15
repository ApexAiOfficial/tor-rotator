# Architecture

## Goals

1. Never report a rotation or an exit as good when it is not.
2. Keep every independently observable fact separate (accepted, applied, verified, changed).
3. Fail closed on every parse, policy and protocol edge.
4. Minimise trust: no runtime dependencies, no shell, no daemon management, least privilege.

## Module map

| Module | Responsibility | Depends on |
| --- | --- | --- |
| `config.py` | TOML loading, strict typing, semantic/security validation, secret resolution | stdlib |
| `control.py` | Tor Control Protocol client: framing, auth, GETINFO, NEWNYM confirmation | `_net`, `config`, `models` |
| `socks.py` | SOCKS5 client (RFC 1928/1929), domain-name addressing | `_net`, `config` |
| `transport.py` | HTTPS GET over SOCKS with a total deadline and size limits | `socks` |
| `providers.py` | Built-in/custom IP-echo endpoints and strict parsers | `config` |
| `consensus.py` | Pure consensus evaluation over observations | `models` |
| `verify.py` | Runs providers sequentially, applies consensus | `providers`, `transport`, `consensus` |
| `service.py` | Health checks, rotation state machine, scheduler | everything above, `lock`, `state`, `metrics` |
| `state.py` | Atomic JSON state, counters | `models` |
| `metrics.py` | Prometheus text rendering | `state` |
| `lock.py` | `flock(2)` single-writer lock | stdlib |
| `cli.py` | Commands, JSON output, exit codes, signals | `service` |

The dependency graph is acyclic, and `consensus.py` has no I/O at all, which is why it can
be property-tested exhaustively.

## Rotation state machine

```text
          ┌──────────────┐
          │ acquire lock │──── held elsewhere ───► LockBusyError (exit 5), nothing changed
          └──────┬───────┘
                 ▼
        verify(before)           record before.ok / before.ip (may fail; rotation continues)
                 ▼
     connect + authenticate ──── failure ───► error "NEWNYM request failed", accepted=false
                 ▼
   SETEVENTS SIGNAL; SIGNAL NEWNYM ── non-250 ──► accepted=false
                 ▼ 250 OK (accepted=true)
  discard events read before the 250
                 ▼
  wait ≤ signal_event_timeout for 650 SIGNAL NEWNYM
        │ received                       │ timeout / connection lost
        ▼                                ▼
   applied=true                     applied=false, error=detail
   sleep(settle)                    one diagnostic verification
        ▼                                ▼
  verify(after) up to N attempts   ┌───────────────────────────┐
  until ok (and changed, if        │ policy: after.ok?         │
  require_exit_change and          │ require_exit_change:      │
  before was verified)             │   before.ok and ip differ │
        └──────────────► policy ───┘
                           ▼
          exit_changed = before.ip != after.ip   (only if both verified, else null)
                           ▼
          read previous state (corrupt → warning, counters reset)
          write state atomically; write metrics      (failures → warnings)
                           ▼
                 release lock, log, return RotationResult
```

`operation_succeeded = accepted ∧ applied ∧ verified ∧ error is None`, and
`successful_change = operation_succeeded ∧ exit_changed is True`.

## Why the `650` event must follow the `250`

Tor's `SIGNAL` handler writes `250 OK` to the controller and only then acts on the signal.
The `650 SIGNAL NEWNYM` event that results from *this* request is therefore always queued
after the acknowledgement. Any `SIGNAL` event read before the acknowledgement came from
earlier activity, such as another controller's `NEWNYM`, and must not be taken as
confirmation. 1.x accepted it.

When NEWNYM is rate-limited (within 10 s of the previous application), Tor schedules the
request for later rather than discarding it, and emits the event when it applies it. The
12 s default confirmation window covers that deferral. Ignored signals (for example, client
functionality disabled) never produce the event.

## Verification model

- **One isolation bucket.** Every probe presents the same SOCKS credentials. Tor isolates
  circuits by SOCKS credentials (`IsolateSOCKSAuth`, on by default), so probes never share a
  circuit with applications but do share one with each other.
- **Sequential probes.** The first probe makes Tor select or build a circuit and later probes
  reuse it. Concurrent first requests right after `NEWNYM` can cause several circuits to be
  built in parallel, which is exactly the disagreement that strict consensus rejects.
- **Re-sampling.** One bucket does not *pin* a circuit: Tor may move an individual stream to
  another circuit, for example when an exit refuses a destination. Live testing against
  Tor 0.4.9 showed providers disagreeing right after bootstrap. Because Tor prefers the most
  recently used circuit of a bucket, a fresh sequential round normally converges on one
  exit, so a disagreement-only failure is re-sampled up to `verify.max_rounds` times. A
  Tor-negative result is final, and provider failures are left to the rotation's own retry
  loop.
- **Consensus.** See the rules in `consensus.py` and the README. The decisive change from 1.x
  is that Tor confirmation is *bound to the consensus IP*.
- **Exit addresses must be global.** `ipaddress.is_global` rejects private, loopback,
  link-local, CGNAT, documentation and reserved ranges, and IPv4-mapped IPv6 addresses are
  canonicalised to IPv4.
- **IPv4-only endpoints.** IP-only built-ins use IPv4-only hostnames so that a dual-stack
  endpoint cannot report an IPv6 address while its peers report IPv4.

## Transport design

The standard library's `http.client` sends requests over a socket produced by the SOCKS5
client and wrapped by `ssl`. This removes environment-proxy, `.netrc` and redirect behaviour
by construction. The SOCKS5 client offers only username/password authentication (Tor accepts
any pair and uses it as an isolation key) and always sends hostnames as `ATYP=0x03`, so the
process never resolves names itself.

A per-operation socket timeout cannot bound a request on its own: a peer that trickles one
byte just inside each timeout could keep a probe alive almost indefinitely. A watchdog timer
therefore shuts the socket down (`socket.shutdown(SHUT_RDWR)` via the base class, so the TLS
object of a concurrent read is left intact) when the total deadline passes. The guarded
socket is released under a lock before it is closed, so the watchdog can never act on a
reused descriptor.

## Persistence

State and metrics are written with `mkstemp` in the target directory, `fsync`, `chmod`,
`rename`, then an `fsync` of the directory. A crash leaves either the old file or the new
one. Reads use `O_NOFOLLOW` and a size cap. A corrupt state file never blocks rotation: the
counters reset and the result carries a warning.

## Failure semantics

- Control or authentication failure: no fallbacks (no shell, no reload); the rotation
  fails with `signal_accepted=false`.
- Verification failure: never reported as a successful rotation.
- Provider disagreement or a tie: no consensus (strict mode fails on any dissent).
- Tor-negative observation: always fatal.
- Concurrent writers: rejected by `flock(2)` with a distinct exit code.
- Programming errors: surface with a traceback in logs. `watch` survives them, and the CLI
  keeps its JSON error contract (exit 4).

## Design decisions

| Decision | Alternatives considered | Reason |
| --- | --- | --- |
| Own control-protocol client | stem | Unmaintained dependency surface; we need ~6 commands and want fail-closed parsing. |
| Own SOCKS5/HTTPS stack | requests + PySocks | PySocks is unmaintained; requests adds env-proxy/netrc/redirect behaviour we would have to disable; zero dependencies simplifies audits. |
| Sequential probes | parallel probes | Parallel first requests after NEWNYM can split across circuits. |
| Strict unanimity by default | plurality | An exit is either known or not; disagreement is a signal, not noise to vote away. |
| UNIX sockets + `PrivateNetwork=yes` | loopback TCP + IP filtering | The service can then send no packet at all except through Tor's sockets. Both are supported. |
| JSON on stdout, logs on stderr | mixed output | Safe to pipe into `jq` and parse in automation. |
