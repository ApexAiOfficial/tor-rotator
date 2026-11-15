#!/usr/bin/env bash
# Regenerate the hash-pinned, cross-platform CI/dev toolchain lock from pyproject.toml.
# The lock is "universal": one file valid for every supported Python (3.11+) and platform.
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile pyproject.toml --group dev --universal --generate-hashes \
  --python-version 3.11 --no-header --quiet -o requirements/dev.txt
sed -i '1i # Hash-pinned CI/dev toolchain (the package itself has no runtime dependencies).\n# Regenerate with: scripts/lock.sh' requirements/dev.txt
echo "requirements/dev.txt updated"
