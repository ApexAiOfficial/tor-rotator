# Testing

## Layers

| Layer | Where | Network | Runs in CI |
| --- | --- | --- | --- |
| Unit and property tests | `tests/test_consensus.py`, `test_providers.py`, `test_config.py`, … | none | every push and PR, Python 3.11–3.14 |
| Protocol and integration tests over real sockets | `tests/test_control.py`, `test_socks.py`, `test_transport.py`, `test_verify.py`, `test_service.py`, `test_cli.py` | loopback only | every push and PR |
| Documentation drift tests | `tests/test_docs.py` | none | every push and PR |
| Live tests against real Tor | `tests/live/` | Tor network | weekly and on demand (`live-tor.yml`) |

## Protocol-level fakes

`tests/fakes.py` provides:

- **`FakeTorControl`**: a threaded control port over TCP or a UNIX socket. It implements
  PROTOCOLINFO, AUTHCHALLENGE/AUTHENTICATE (SAFECOOKIE computed with an *independent*
  implementation of the spec, HASHEDPASSWORD, NULL), GETINFO with data blocks and
  dot-stuffing, SETEVENTS, and scriptable `SIGNAL NEWNYM` behaviours: immediate, stale
  (event before the acknowledgement), ignored, delayed, interleaved noise, connection drop,
  rejection and protocol violation.
- **`FakeSocks`**: a SOCKS5 proxy that records the requested address type, host, port and
  credentials, tunnels to an upstream, and can misbehave on demand (method rejection,
  unoffered method, bad version, authentication failure, reply codes including Tor's
  extended codes, unusual bound addresses).
- **`FakeHttps`**: TLS IP-echo servers for every provider hostname, with certificates from a
  per-session test CA (`trustme`). They support status codes, chunked responses, oversize
  bodies and slow-drip responses.

Because these are real sockets speaking real protocols, the production timeout, TLS
verification and parsing paths run unmodified.

## Regression tests for 1.0.1 defects

Search for `regression` in the test suite. Each one fails against the 1.0.1 logic:
consensus binding, tie-breaking, `IsTor` string coercion, unverified exit comparison,
`require_exit_change` with an unverified "before", stale NEWNYM events, and QuotedString
decoding.

## Running

```bash
python -m pytest                       # all offline tests (live tests are deselected)
python -m pytest --cov                 # with branch coverage; fails under 95%
python -m pytest -k consensus -x       # focus
scripts/check.sh test                  # what CI runs
```

Warnings are errors (`filterwarnings = error`), so a leaked socket (`ResourceWarning`) or an
exception in a server thread fails the suite.

## Live tests

```bash
scripts/live-tor.sh            # needs `tor` locally; starts a private instance in a temp dir
scripts/live-tor-docker.sh     # no local Tor: runs everything in a disposable Debian container
```

`scripts/live-tor.sh` starts Tor with a temporary DataDirectory, TCP and UNIX control and
SOCKS listeners, and both SAFECOOKIE and HASHEDPASSWORD authentication. After bootstrap it
runs `pytest -m live tests/live`, which covers:

- `doctor` health in TCP/TCP, UNIX/UNIX and TCP/UNIX modes, with SAFECOOKIE and HASHEDPASSWORD;
- unanimous, Tor-confirmed verification;
- rotation with prompt NEWNYM confirmation, `watch --once`, and the metrics file;
- **deferred NEWNYM**: a second NEWNYM within Tor's rate-limit window is confirmed after
  Tor's deferral, and a short window reports the deferral honestly;
- a verified exit change within a few rotations;
- the CLI end to end via `python -m tor_rotator`.

Live tests contact the Tor network and public IP-echo services; they are opt-in for that
reason.
