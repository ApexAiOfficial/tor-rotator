#!/usr/bin/env bash
# Run the live test-suite against a private, throwaway Tor client.
#
# Starts `tor` with a temporary DataDirectory, TCP and UNIX control/SOCKS listeners,
# SAFECOOKIE *and* HASHEDPASSWORD authentication, waits for bootstrap, then runs
# `pytest -m live tests/live`. Everything lives in one temp dir that is removed on exit.
#
# Requirements: tor on PATH, and a Python with tor-rotator and the test group installed.
# Usage: scripts/live-tor.sh [extra pytest args]
#   PYTHON=.venv/bin/python scripts/live-tor.sh -x
set -euo pipefail

PY="${PYTHON:-python3}"
SOCKS_PORT="${TOR_ROTATOR_LIVE_SOCKS_PORT:-19050}"
CONTROL_PORT="${TOR_ROTATOR_LIVE_CONTROL_PORT:-19051}"
BOOTSTRAP_TIMEOUT="${TOR_ROTATOR_LIVE_BOOTSTRAP_TIMEOUT:-240}"

command -v tor >/dev/null || { echo "tor is not installed" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/trl.XXXXXX")"
chmod 700 "$WORK"
TOR_PID=""
cleanup() {
  if [[ -n "$TOR_PID" ]]; then
    kill "$TOR_PID" 2>/dev/null || true
    wait "$TOR_PID" 2>/dev/null || true
  fi
  rm -rf -- "${WORK:?}"
}
trap cleanup EXIT

PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HASH="$(tor --quiet --hash-password "$PASSWORD" | tail -n 1)"

cat >"$WORK/torrc" <<EOF
DataDirectory $WORK/data
SocksPort 127.0.0.1:$SOCKS_PORT
SocksPort unix:$WORK/socks
ControlPort 127.0.0.1:$CONTROL_PORT
ControlSocket $WORK/control
CookieAuthentication 1
CookieAuthFile $WORK/control.authcookie
HashedControlPassword $HASH
SafeSocks 1
Log notice file $WORK/tor.log
EOF

tor -f "$WORK/torrc" --RunAsDaemon 0 >/dev/null 2>&1 &
TOR_PID=$!

echo "waiting up to ${BOOTSTRAP_TIMEOUT}s for Tor to bootstrap..."
for _ in $(seq 1 "$BOOTSTRAP_TIMEOUT"); do
  if grep -q "Bootstrapped 100%" "$WORK/tor.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$TOR_PID" 2>/dev/null; then
    echo "tor exited early:" >&2
    tail -n 30 "$WORK/tor.log" >&2 || true
    exit 1
  fi
  sleep 1
done
if ! grep -q "Bootstrapped 100%" "$WORK/tor.log"; then
  echo "Tor did not bootstrap in time:" >&2
  tail -n 30 "$WORK/tor.log" >&2
  exit 1
fi
grep -m1 "Tor .* running on" "$WORK/tor.log" || true

export TOR_ROTATOR_LIVE_DIR="$WORK"
export TOR_ROTATOR_LIVE_PASSWORD="$PASSWORD"
export TOR_ROTATOR_LIVE_SOCKS_PORT="$SOCKS_PORT"
export TOR_ROTATOR_LIVE_CONTROL_PORT="$CONTROL_PORT"
"$PY" -m pytest -m live tests/live -v -rP -p no:cacheprovider -o addopts="-ra --strict-markers" "$@"
