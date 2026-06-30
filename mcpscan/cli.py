"""Command-line interface for mcpscan."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .findings import Severity
from .report import render
from .scanner import scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpscan",
        description="Supply-chain security scanner for MCP servers and Claude Code projects.",
    )
    p.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text",
                   help="output format (default: text)")
    p.add_argument("--json", action="store_true", help="shorthand for --format json")
    p.add_argument("-o", "--output", help="write report to this file instead of stdout")
    p.add_argument("--min-severity", default="low",
                   help="minimum severity that causes a non-zero exit "
                        "(info|low|medium|high|critical; default: low)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-V", "--version", action="version", version=f"mcpscan {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.exists(args.path):
        print(f"mcpscan: path not found: {args.path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        threshold = Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"mcpscan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    fmt = "json" if args.json else args.format
    report = scan(args.path)

    color = (not args.no_color) and args.output is None and sys.stdout.isatty()
    text = render(report, fmt, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"mcpscan: wrote {fmt} report to {args.output}", file=sys.stderr)
    else:
        # Force UTF-8 so redaction/box glyphs survive a Windows console.
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        print(text)

    return EXIT_FINDINGS if report.at_or_above(threshold) else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
