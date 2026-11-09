"""Command line interface: ``trailtriage <path> [options]``."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .events import ParseError, load_path
from .report import exit_code, render_json, render_markdown, render_text
from .rules import run_rules
from .scoring import score_principals

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trailtriage",
        description="Offline AWS CloudTrail triage: find identity-based attack patterns and the "
        "multi-stage chains that hide behind single-event noise. No AWS credentials, no network.",
        epilog="Example: trailtriage ~/cloudtrail/ --window 24 --format text --fail-on high",
    )
    parser.add_argument("path", help="CloudTrail .json/.jsonl/.gz file, or a directory to walk")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=24,
        metavar="HOURS",
        help="correlation window for chain detection in hours (default: 24)",
    )
    parser.add_argument(
        "--min-grade",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="only report principals at or above this grade (default: low)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        metavar="N",
        help="show only the N worst principals in text/markdown output (default: 0 = all)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="exit 1 if any principal reaches this grade, for CI gating (default: none)",
    )
    parser.add_argument("--output", metavar="FILE", help="write the report to FILE instead of stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress parse warnings on stderr")
    parser.add_argument("--version", action="version", version=f"trailtriage {__version__}")
    return parser


def _filter(scores, min_grade: str):
    order = ["low", "medium", "high", "critical"]
    threshold = order.index(min_grade)
    return [s for s in scores if order.index(s.grade) >= threshold]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        events, warnings = load_path(args.path)
    except ParseError as exc:
        print(f"trailtriage: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        for warning in warnings:
            print(f"trailtriage: warning: {warning}", file=sys.stderr)

    principal_count = len({ev.principal for ev in events})
    findings = run_rules(events, window_hours=args.window)
    scores = _filter(score_principals(findings), args.min_grade)

    if args.format == "json":
        report = render_json(scores, len(events), principal_count)
    elif args.format == "markdown":
        report = render_markdown(scores, len(events), principal_count, top=args.top)
    else:
        report = render_text(scores, len(events), principal_count, top=args.top)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
        if not args.quiet:
            print(f"trailtriage: wrote {args.output}", file=sys.stderr)
    else:
        print(report, end="" if report.endswith("\n") else "\n")

    return exit_code(scores, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
