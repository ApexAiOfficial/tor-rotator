# Contributing

Thanks for helping improve Tor Rotator. This project values correctness and fail-closed
behaviour over features, so expect careful review.

## Ground rules

- **Security issues:** report them privately (see [SECURITY.md](SECURITY.md)), never in a
  public issue or pull request.
- **No runtime dependencies.** The package deliberately depends only on the standard
  library. Proposals that add one need a strong justification.
- **Never weaken a safety check silently.** If a change relaxes validation, consensus or
  authentication behaviour, call it out explicitly in the pull request and the changelog.
- Be respectful; see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements/dev.txt
pip install --no-deps --no-build-isolation -e .
pre-commit install   # optional: ruff on every commit
```

## Before you open a pull request

```bash
scripts/check.sh     # lint, format, mypy --strict, tests + coverage, packaging, security
```

- Add or update tests for every behaviour change. Bug fixes need a regression test that
  fails without the fix. Coverage must stay at or above 95% (branch).
- If you touched the control protocol or the transport, also run the live suite if you can:
  `scripts/live-tor-docker.sh` (Docker) or `scripts/live-tor.sh` (local Tor).
- Update `README.md`, `config.example.toml` and `docs/` when you change behaviour,
  configuration or output. `tests/test_docs.py` checks that every config key is documented.
- Add an entry under an `Unreleased` heading in `CHANGELOG.md`.
- Keep commits focused, with imperative-mood subjects (`fix: …`, `feat: …`, `docs: …`).

## Toolchain updates

The CI toolchain is pinned with hashes in `requirements/dev.txt`. After changing the
dependency groups in `pyproject.toml`, regenerate it with `scripts/lock.sh` (requires
[uv](https://docs.astral.sh/uv/)). Dependabot proposes routine updates.

## Reporting bugs and requesting features

Use the issue templates. For bugs, include `tor-rotator --version`, your Tor version, the
redacted output of `tor-rotator config`, and the JSON result plus stderr log of the failing
command.
