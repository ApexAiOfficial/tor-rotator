# Releasing

Releases are cut from `main` by pushing a `vX.Y.Z` tag. The `release` workflow then
re-runs every gate, builds the sdist and wheel, generates `SHA256SUMS`, attests build
provenance, and publishes a GitHub Release with notes taken from `CHANGELOG.md`.

## Checklist

1. `main` is green (CI and Security workflows).
2. Bump `src/tor_rotator/_version.py`.
3. Move the `Unreleased` changelog entries under `## [X.Y.Z] - YYYY-MM-DD` and add the
   comparison link at the bottom.
4. Run the gates locally:
   ```bash
   scripts/check.sh
   python scripts/check_release.py --tag vX.Y.Z
   scripts/live-tor-docker.sh        # recommended for control/transport changes
   ```
5. Commit (`release: vX.Y.Z`), push, wait for green CI.
6. Tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
7. Verify the published artifacts:
   ```bash
   gh release download vX.Y.Z --repo ApexAiOfficial/tor-rotator
   sha256sum --check SHA256SUMS
   gh attestation verify tor_rotator-X.Y.Z-py3-none-any.whl --repo ApexAiOfficial/tor-rotator
   ```

## Versioning

Semantic Versioning. Changes to the CLI's JSON field names, exit codes or configuration keys
are breaking. So is any change that makes a previously valid configuration invalid. Treat
stricter validation as a breaking change unless it closes a security hole.

## PyPI

The package is not published to PyPI yet. If it is, use PyPI Trusted Publishing (OIDC) from
the release workflow with a protected `pypi` environment. Never use a long-lived API token.
