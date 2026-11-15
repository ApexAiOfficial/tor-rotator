"""Documentation must not drift from the code."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from dataclasses import fields
from pathlib import Path

import pytest

from tor_rotator import __version__
from tor_rotator.cli import build_parser
from tor_rotator.config import (
    BUILTIN_PROVIDERS,
    AppConfig,
    ControlConfig,
    RotationConfig,
    RuntimeConfig,
    SocksConfig,
    VerifyConfig,
)
from tor_rotator.errors import ExitCode

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
EXAMPLE = (ROOT / "config.example.toml").read_text(encoding="utf-8")
SECTIONS = {
    "control": ControlConfig,
    "socks": SocksConfig,
    "verify": VerifyConfig,
    "rotation": RotationConfig,
    "runtime": RuntimeConfig,
}


@pytest.mark.parametrize("path", ["config.example.toml", "deploy/config.debian.toml"])
def test_shipped_configs_load_and_validate(path):
    AppConfig.load(ROOT / path)


def test_example_config_matches_built_in_defaults():
    assert AppConfig.load(ROOT / "config.example.toml") == AppConfig()


@pytest.mark.parametrize(("section", "cls"), SECTIONS.items())
def test_every_config_key_is_documented(section, cls):
    for field in fields(cls):
        if field.name == "custom_providers":
            assert "[verify.custom_providers" in EXAMPLE
            assert "verify.custom_providers" in README
            continue
        assert re.search(rf"^#?\s*{field.name}\s*=", EXAMPLE, re.MULTILINE), (
            f"{section}.{field.name} missing from config.example.toml"
        )
        assert f"`{field.name}`" in README or field.name in README, (
            f"{section}.{field.name} missing from README"
        )


def test_every_command_is_documented():
    commands = build_parser()._subparsers._group_actions[0].choices  # type: ignore[union-attr]
    for name in commands:
        assert re.search(rf"^\s+{name}\s", README, re.MULTILINE), f"command {name} missing from README usage"


def test_every_exit_code_is_documented():
    for code in ExitCode:
        if code is not ExitCode.USAGE:
            assert f"| `{int(code)}` |" in README, f"exit code {int(code)} missing from README"


def test_builtin_providers_are_documented():
    for name in BUILTIN_PROVIDERS:
        assert f"`{name}`" in README


def test_changelog_top_entry_is_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    top = re.search(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.MULTILINE)
    assert top is not None
    assert top.group(1) == __version__


def test_pyproject_metadata():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    assert project["dependencies"] == []
    assert project["scripts"]["tor-rotator"] == "tor_rotator.cli:main"
    assert "version" in project["dynamic"]


def test_release_check_script_passes():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release.py"), "--tag", f"v{__version__}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_release_check_script_rejects_wrong_tag():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release.py"), "--tag", "v0.0.0"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1
    assert "does not match" in result.stderr


def test_relative_links_in_markdown_resolve():
    for doc in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), ROOT / "SECURITY.md"]:
        for target in re.findall(r"\]\((?!https?://|#|mailto:)([^)#\s]+)", doc.read_text(encoding="utf-8")):
            assert (doc.parent / target).exists(), f"{doc.name}: broken link {target}"
