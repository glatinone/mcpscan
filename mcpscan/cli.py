"""Command-line interface for mcpscan."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .discover import render_discovery_json, render_discovery_text, run_discovery
from .findings import Severity
from .fixer import apply_fixes, compute_fixes, render_preview
from .report import render
from .scanner import scan_files

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
    p.add_argument("--list-rules", action="store_true", help="list all rules and exit")
    p.add_argument("--fix", action="store_true",
                   help="preview mechanical one-line fixes for fixable findings (dry run)")
    p.add_argument("--apply-fix", action="store_true",
                   help="write the fixes shown by --fix to disk (implies --fix)")
    p.add_argument("--discover", action="store_true",
                   help="scan known MCP client config locations on this machine "
                        "(Claude Desktop, Claude Code, Cursor, VS Code, Windsurf) "
                        "instead of a path — closes OWASP MCP09:2025 (Shadow MCP Servers)")
    p.add_argument("-V", "--version", action="version", version=f"mcpscan {__version__}")
    return p


def list_rules() -> str:
    from . import rules as rules_pkg
    from .rules.base import Rule
    rows = sorted(rules_pkg.all_rules(), key=lambda r: r.id)
    lines = [f"{'ID':<8} {'SEVERITY':<9} {'FIX':<5} {'OWASP':<10} NAME",
              f"{'-'*8} {'-'*9} {'-'*5} {'-'*10} {'-'*40}"]
    for r in rows:
        fixable = "yes" if type(r).fix_line is not Rule.fix_line else "-"
        lines.append(f"{r.id:<8} {r.severity.label:<9} {fixable:<5} {r.owasp or '-':<10} {r.name}")
    lines.append(f"\n{len(rows)} rules.")
    return "\n".join(lines)


def _run_discover(args: argparse.Namespace, fmt: str, color: bool, threshold: Severity) -> int:
    if args.fix or args.apply_fix:
        print("mcpscan: --discover does not support --fix/--apply-fix yet", file=sys.stderr)
        return EXIT_ERROR
    if fmt == "sarif":
        print("mcpscan: --discover supports text/json output only (sarif not yet supported)",
              file=sys.stderr)
        return EXIT_ERROR
    if args.path != ".":
        print(f"mcpscan: --discover ignores the path argument ('{args.path}') — "
              f"it scans known client config locations, not a project directory",
              file=sys.stderr)

    discovery = run_discovery()
    text = render_discovery_json(discovery) if fmt == "json" else render_discovery_text(discovery, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"mcpscan: wrote {fmt} discovery report to {args.output}", file=sys.stderr)
    else:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        print(text)

    at_or_above = any(f.severity >= threshold for f in discovery.all_findings())
    return EXIT_FINDINGS if at_or_above else EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return EXIT_OK

    try:
        threshold = Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"mcpscan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    fmt = "json" if args.json else args.format
    color = (not args.no_color) and args.output is None and sys.stdout.isatty()

    if args.discover:
        return _run_discover(args, fmt, color, threshold)

    if not os.path.exists(args.path):
        print(f"mcpscan: path not found: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    report, files = scan_files(args.path)

    if args.fix or args.apply_fix:
        fixes = compute_fixes(report, files)
        print(render_preview(fixes))
        if args.apply_fix and fixes:
            modified = apply_fixes(fixes, files)
            print(f"\nmcpscan: applied {len(fixes)} fix(es) across {len(modified)} file(s).",
                  file=sys.stderr)
        return EXIT_FINDINGS if report.at_or_above(threshold) else EXIT_OK

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
