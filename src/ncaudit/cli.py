"""Command-line interface.

Exit codes: 0 no findings at or above --fail-on, 1 findings at or above --fail-on,
2 invalid usage or a file could not be audited.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ncaudit import __version__
from ncaudit.errors import NCAuditError
from ncaudit.models import Severity
from ncaudit.parser import read_config
from ncaudit.report import FileResult, render_json, render_rules, render_text
from ncaudit.rules import RULES, audit

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
_LEVELS = [s.label for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ncaudit",
        description="Offline security and operational audit of Cisco IOS / IOS XE configuration files.",
        epilog="Exit codes: 0 = no findings at or above --fail-on, 1 = findings found, 2 = error.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("audit", help="audit one or more configuration files")
    p.add_argument("files", nargs="+", metavar="FILE", help="saved IOS/IOS XE configuration (text)")
    p.add_argument("-f", "--format", choices=("text", "json"), default="text", help="report format (default: text)")
    p.add_argument("-s", "--min-severity", choices=_LEVELS, default="low",
                   help="only report findings at or above this level (default: low)")
    p.add_argument("--fail-on", choices=[*_LEVELS, "none"], default="low",
                   help="exit with code 1 if a reported finding is at or above this level (default: low)")

    p = sub.add_parser("rules", help="list the audit rules")
    p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Paths and evidence can hold characters the console code page cannot encode; never crash on print.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    if args.command == "rules":
        print(render_rules(RULES, args.format == "json"))
        return EXIT_OK

    minimum = Severity.parse(args.min_severity)
    results: list[FileResult] = []
    for path in args.files:
        try:
            findings = [f for f in audit(read_config(path)) if f.severity >= minimum]
            results.append(FileResult(path, findings))
        except NCAuditError as exc:
            results.append(FileResult(path, error=str(exc)))
            print(f"ncaudit: error: {path}: {exc}", file=sys.stderr)

    print(render_json(results) if args.format == "json" else render_text(results))
    if any(r.error for r in results):
        return EXIT_ERROR
    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for r in results for f in r.findings):
            return EXIT_FINDINGS
    return EXIT_OK
