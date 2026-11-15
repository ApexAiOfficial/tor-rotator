#!/usr/bin/env python3
"""Release-readiness check: version, changelog and (optionally) tag must agree.

Usage: python scripts/check_release.py [--tag vX.Y.Z]
Exit status is non-zero with a list of problems if anything is inconsistent.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$")


def package_version() -> str:
    text = (ROOT / "src" / "tor_rotator" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', text, re.MULTILINE)
    if not match:
        raise SystemExit("cannot find __version__ in src/tor_rotator/_version.py")
    return match.group(1)


def changelog_versions() -> list[str]:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return re.findall(r"^## \[?(\d+\.\d+\.\d+[^\] ]*)\]? - \d{4}-\d{2}-\d{2}", text, re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="git tag being released, e.g. v2.0.0")
    args = parser.parse_args()

    problems: list[str] = []
    version = package_version()
    if not SEMVER.match(version):
        problems.append(f"version {version!r} is not a release version")

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    if "version" not in project.get("dynamic", []):
        problems.append("pyproject.toml must take the version dynamically from tor_rotator._version")
    if project.get("dependencies"):
        problems.append("runtime dependencies were added; update README/SECURITY supply-chain claims")

    released = changelog_versions()
    if not released:
        problems.append("CHANGELOG.md has no dated release entries")
    elif released[0] != version:
        problems.append(f"newest CHANGELOG.md entry is {released[0]}, package version is {version}")

    if args.tag is not None and args.tag != f"v{version}":
        problems.append(f"tag {args.tag} does not match package version v{version}")

    for problem in problems:
        print(f"release check: {problem}", file=sys.stderr)
    if not problems:
        print(f"release check: OK (version {version})")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
