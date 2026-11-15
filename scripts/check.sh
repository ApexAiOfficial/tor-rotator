#!/usr/bin/env bash
# Every release-blocking quality gate, in one place. CI runs exactly this script, so a
# green local run means a green CI run.
#
# Usage: scripts/check.sh [lint|types|test|package|security|all]   (default: all)
# Requires the toolchain from requirements/dev.txt in the active Python environment
# (PYTHON=... selects the interpreter; default: python3).
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
STAGE="${1:-all}"
DIST="${DIST_DIR:-dist}"

step() { printf '\n==> %s\n' "$*"; }

lint() {
  step "ruff lint"
  "$PY" -m ruff check src tests scripts
  step "ruff format --check"
  "$PY" -m ruff format --check src tests scripts
}

types() {
  step "mypy --strict"
  "$PY" -m mypy
}

test_suite() {
  step "pytest (branch coverage, fail under 95%)"
  "$PY" -m pytest --cov --cov-report=term-missing --cov-report=xml
}

package() {
  step "release metadata consistency"
  "$PY" scripts/check_release.py
  step "build sdist + wheel (no build isolation: pinned setuptools)"
  rm -rf -- "${DIST:?}"
  "$PY" -m build --no-isolation --outdir "$DIST" .
  step "twine check --strict"
  "$PY" -m twine check --strict "$DIST"/*
  step "check-wheel-contents"
  "$PY" -m check_wheel_contents "$DIST"/*.whl
  step "install wheel into a clean venv and smoke-test the console script"
  local venv
  venv="$(mktemp -d)"
  "$PY" -m venv "$venv"
  "$venv/bin/python" -m pip install -q --no-index --no-deps "$DIST"/*.whl
  "$venv/bin/tor-rotator" --version
  "$venv/bin/tor-rotator" --config config.example.toml config >/dev/null
  "$venv/bin/tor-rotator" --config deploy/config.debian.toml config >/dev/null
  "$venv/bin/python" -c "import tor_rotator, sys; assert not [m for m in sys.modules if m.split('.')[0] in {'requests','socks','urllib3'}]"
  rm -rf -- "${venv:?}"
}

security() {
  step "pip-audit (hash-pinned toolchain)"
  "$PY" -m pip_audit --strict --require-hashes --disable-pip -r requirements/dev.txt
  step "actionlint"
  "$PY" -m actionlint_py 2>/dev/null || actionlint
  step "zizmor (GitHub Actions security)"
  "$PY" -m zizmor --offline --min-severity low .github/workflows
}

case "$STAGE" in
  lint) lint ;;
  types) types ;;
  test) test_suite ;;
  package) package ;;
  security) security ;;
  all) lint; types; test_suite; package; security ;;
  *) echo "unknown stage: $STAGE" >&2; exit 2 ;;
esac
step "OK ($STAGE)"
