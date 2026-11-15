#!/usr/bin/env bash
# Run scripts/live-tor.sh inside a disposable Debian container (no local Tor install needed).
# The repository is mounted read-only and copied inside the container.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${TOR_ROTATOR_LIVE_IMAGE:-debian:trixie-slim}"
exec docker run --rm -v "$PWD:/src:ro" -e PIP_DISABLE_PIP_VERSION_CHECK=1 "$IMAGE" bash -euo pipefail -c '
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    tor python3 python3-venv ca-certificates >/dev/null
  mkdir -p /work
  tar -C /src --exclude=.venv --exclude=.git --exclude="*.egg-info" -cf - . | tar -C /work -xf -
  cd /work
  python3 -m venv /venv
  /venv/bin/pip install -q --require-hashes -r requirements/dev.txt
  /venv/bin/pip install -q --no-deps --no-build-isolation -e .
  tor --version | head -n 1
  PYTHON=/venv/bin/python scripts/live-tor.sh "$@"
' live-tor "$@"
