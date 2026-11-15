#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one version (used for GitHub release notes)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def section(version: str) -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[[^\]]+\]: |\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise SystemExit(f"no CHANGELOG.md section for {version}")
    return match.group(1).strip() + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: release_notes.py X.Y.Z")
    sys.stdout.write(section(sys.argv[1]))
