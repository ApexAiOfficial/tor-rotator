"""Prometheus text-format metrics rendered from persisted state.

Intended for node_exporter's textfile collector (``runtime.metrics_file``) or ad-hoc use
(``tor-rotator metrics``). Exit IP addresses are deliberately never exported: they
would be unbounded label cardinality and needless operational data.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ._version import __version__
from .state import atomic_write_text


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, int | float):
        return float(value)
    return None


def _timestamp(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.timestamp() if parsed.tzinfo is not None else None


def _format(value: float) -> str:
    return str(int(value)) if value.is_integer() else repr(value)


def render(state: dict[str, Any] | None) -> str:
    """Render *state* (as written by :func:`tor_rotator.state.record_rotation`)."""
    state = state or {}
    counters_raw = state.get("counters")
    counters: dict[str, Any] = counters_raw if isinstance(counters_raw, dict) else {}
    last_raw = state.get("last_rotation")
    last: dict[str, Any] = last_raw if isinstance(last_raw, dict) else {}
    after_raw = last.get("after")
    after: dict[str, Any] = after_raw if isinstance(after_raw, dict) else {}

    lines: list[str] = []

    def metric(name: str, kind: str, help_text: str, samples: list[tuple[str, float | None]]) -> None:
        present = [(labels, value) for labels, value in samples if value is not None]
        if not present:
            return
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        lines.extend(f"{name}{labels} {_format(value)}" for labels, value in present)

    metric(
        "tor_rotator_build_info",
        "gauge",
        "Tor Rotator build information.",
        [(f'{{version="{__version__}"}}', 1.0)],
    )
    metric(
        "tor_rotator_rotations_total",
        "counter",
        "Rotation attempts by outcome.",
        [
            ('{outcome="succeeded"}', _number(counters.get("rotations_succeeded", 0))),
            ('{outcome="failed"}', _number(counters.get("rotations_failed", 0))),
        ],
    )
    metric(
        "tor_rotator_exit_changes_total",
        "counter",
        "Rotations that moved to a different verified exit IP.",
        [("", _number(counters.get("exit_changes_total", 0)))],
    )
    metric(
        "tor_rotator_consecutive_failures",
        "gauge",
        "Failed rotations since the last success.",
        [("", _number(state.get("consecutive_failures", 0)))],
    )
    metric(
        "tor_rotator_last_rotation_timestamp_seconds",
        "gauge",
        "Completion time of the last rotation attempt.",
        [("", _timestamp(last.get("completed_at")))],
    )
    metric(
        "tor_rotator_last_success_timestamp_seconds",
        "gauge",
        "Completion time of the last successful rotation.",
        [("", _timestamp(state.get("last_success_at")))],
    )
    metric(
        "tor_rotator_last_rotation_success",
        "gauge",
        "Whether the last rotation met its success policy (1) or not (0).",
        [("", _number(last.get("operation_succeeded")))],
    )
    metric(
        "tor_rotator_last_rotation_exit_changed",
        "gauge",
        "Whether the last rotation verified a different exit IP (1) or not (0).",
        [("", _number(last.get("successful_change")))],
    )
    duration = _number(last.get("duration_ms"))
    metric(
        "tor_rotator_last_rotation_duration_seconds",
        "gauge",
        "Wall-clock duration of the last rotation attempt.",
        [("", None if duration is None else duration / 1000.0)],
    )
    metric(
        "tor_rotator_exit_verified",
        "gauge",
        "Whether the exit was verified after the last rotation (1) or not (0).",
        [("", _number(after.get("ok")))],
    )
    return "\n".join(lines) + "\n"


def write(path: str | Path, text: str) -> None:
    """Atomically write a metrics file (mode 0644; it contains no sensitive data)."""
    atomic_write_text(Path(path), text, mode=0o644)
