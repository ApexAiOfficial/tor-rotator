"""Command-line interface.

Machine-readable results go to stdout as JSON; logs go to stderr. Exit codes are
documented in :class:`tor_rotator.errors.ExitCode` and in the README.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from collections.abc import Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from . import metrics
from ._version import __version__
from .config import CONFIG_ENV_VAR, AppConfig
from .errors import ExitCode, TorRotatorError
from .log import configure_logging
from .service import TorRotatorService

LOG = logging.getLogger("tor_rotator")

_EPILOG = """\
exit codes:
  0  success: the operation met its configured success policy
  1  the operation ran but did not succeed (the JSON result explains why);
     for "status", no rotation has been recorded yet
  2  invalid command-line usage
  3  configuration error
  4  runtime error (no result could be produced)
  5  another rotation holds the lock; nothing was changed
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tor-rotator",
        description="Verified Tor circuit rotation: authenticated NEWNYM plus independent, "
        "quorum-based exit verification.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help=f"TOML configuration file (default: ${CONFIG_ENV_VAR}, else built-in defaults)",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON output")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        type=str.upper,
        help="override runtime.log_level",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    sub.add_parser("doctor", help="check control plane, bootstrap, SOCKS wiring and the Tor exit")
    sub.add_parser("verify", help="verify the current Tor exit without rotating")
    sub.add_parser("rotate", help="request NEWNYM and verify the resulting exit")
    sub.add_parser("status", help="show the persisted rotation state")
    watch = sub.add_parser("watch", help="rotate on the configured schedule until stopped")
    watch.add_argument("--once", action="store_true", help="run a single scheduled iteration")
    sub.add_parser("config", help="validate configuration and print the effective settings")
    sub.add_parser("metrics", help="print Prometheus metrics derived from persisted state")
    return parser


def _emit(payload: dict[str, Any], pretty: bool) -> None:
    sys.stdout.write(json.dumps(payload, indent=2 if pretty else None, sort_keys=True) + "\n")
    sys.stdout.flush()


def _emit_error(exc: BaseException, code: ExitCode) -> None:
    payload = {"ok": False, "error": str(exc), "error_type": type(exc).__name__, "exit_code": int(code)}
    sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")


def _run_watch(service: TorRotatorService, once: bool) -> ExitCode:
    def _handle(signum: int, _frame: FrameType | None) -> None:
        if service.stopping:  # second signal: stop waiting for the current rotation
            raise KeyboardInterrupt
        LOG.info("stop requested", extra={"signal": signal.Signals(signum).name})
        service.request_stop()

    previous = {sig: signal.signal(sig, _handle) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        return service.watch(once=once)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _dispatch(args: argparse.Namespace, config: AppConfig) -> ExitCode:
    if args.command == "config":
        _emit({"ok": True, "config": config.to_redacted_dict()}, args.pretty)
        return ExitCode.OK

    service = TorRotatorService(config)
    if args.command == "doctor":
        health = service.health()
        _emit(health.to_dict(), args.pretty)
        return ExitCode.OK if health.healthy else ExitCode.FAILED
    if args.command == "verify":
        verification = service.verify()
        _emit(verification.to_dict(), args.pretty)
        return ExitCode.OK if verification.ok else ExitCode.FAILED
    if args.command == "rotate":
        rotation = service.rotate()
        _emit(rotation.to_dict(), args.pretty)
        return ExitCode.OK if rotation.operation_succeeded else ExitCode.FAILED
    if args.command == "status":
        state = service.state.read()
        if state is None:
            _emit({"state": None, "message": "no rotation state has been recorded"}, args.pretty)
            return ExitCode.FAILED
        _emit(state, args.pretty)
        return ExitCode.OK
    if args.command == "metrics":
        sys.stdout.write(metrics.render(service.state.read()))
        return ExitCode.OK
    if args.command == "watch":
        return _run_watch(service, args.once)
    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``tor-rotator`` console script."""
    args = build_parser().parse_args(argv)
    try:
        config = AppConfig.load(args.config)
        configure_logging(args.log_level or config.runtime.log_level, config.runtime.log_format)
        return int(_dispatch(args, config))
    except KeyboardInterrupt:
        return int(ExitCode.INTERRUPTED)
    except TorRotatorError as exc:
        _emit_error(exc, exc.exit_code)
        return int(exc.exit_code)
    except OSError as exc:
        _emit_error(exc, ExitCode.RUNTIME)
        return int(ExitCode.RUNTIME)
    except Exception as exc:  # keep the JSON error contract for unexpected bugs
        LOG.exception("unexpected internal error")
        _emit_error(exc, ExitCode.RUNTIME)
        return int(ExitCode.RUNTIME)
