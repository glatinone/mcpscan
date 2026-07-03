"""`--fix` mode: generate, preview, and (optionally) apply mechanical patches.

Only a small subset of findings are safe to auto-patch: a one-line value
swap that can't change what a call does besides re-enabling the check it
disabled (dropping a `verify` kwarg pinned to False, swapping `yaml.load` for
`yaml.safe_load`, etc). Anything that requires restructuring a call or
choosing new argument values (turning a shell string into an argv list when a
subprocess call opts into shell execution, replacing `pickle.loads` with a
schema-validated format) is deliberately left alone; see `Rule.fix_line` for
the contract each rule opts into.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Dict, List

from .findings import Finding, Report
from .loaders import FileInfo
from . import rules as rules_pkg


@dataclass(frozen=True)
class Fix:
    finding: Finding
    before: str
    after: str
    explanation: str


def compute_fixes(report: Report, files: List[FileInfo]) -> List[Fix]:
    """Find every finding with a rule-provided mechanical fix for its line."""
    rules_by_id = {r.id: r for r in rules_pkg.all_rules()}
    lines_by_path = {f.relpath: f.lines for f in files}
    fixes: List[Fix] = []

    for finding in report.sorted():
        rule = rules_by_id.get(finding.rule_id)
        if rule is None or not finding.line:
            continue
        lines = lines_by_path.get(finding.path)
        if not lines or finding.line > len(lines):
            continue
        before = lines[finding.line - 1]
        result = rule.fix_line(before)
        if not result:
            continue
        after, explanation = result
        if after == before:
            continue
        fixes.append(Fix(finding=finding, before=before, after=after, explanation=explanation))
    return fixes


def render_preview(fixes: List[Fix]) -> str:
    """Render suggested fixes as per-finding diffs, dry-run style."""
    if not fixes:
        return "mcpscan --fix: no mechanically fixable findings."

    out: List[str] = []
    for fx in fixes:
        out.append(f"{fx.finding.location()}  [{fx.finding.rule_id}] {fx.finding.title}")
        diff = difflib.unified_diff(
            [fx.before + "\n"], [fx.after + "\n"],
            fromfile="before", tofile="after", lineterm="",
        )
        out.extend(line.rstrip("\n") for line in diff
                   if not line.startswith(("---", "+++", "@@")))
        out.append(f"  why: {fx.explanation}")
        out.append("")
    out.append(f"{len(fixes)} fixable finding(s). Re-run with --apply-fix to write these changes.")
    return "\n".join(out)


def apply_fixes(fixes: List[Fix], files: List[FileInfo]) -> List[str]:
    """Write fixes to disk, one line replacement per finding. Returns modified paths."""
    abspath_by_rel = {f.relpath: f.abspath for f in files}
    by_path: Dict[str, List[Fix]] = {}
    for fx in fixes:
        by_path.setdefault(fx.finding.path, []).append(fx)

    modified: List[str] = []
    for relpath, path_fixes in by_path.items():
        abspath = abspath_by_rel.get(relpath)
        if not abspath:
            continue
        with open(abspath, "r", encoding="utf-8", newline="") as fh:
            raw_lines = fh.readlines()

        changed = False
        for fx in path_fixes:
            idx = fx.finding.line - 1
            if idx >= len(raw_lines):
                continue
            ending = ""
            if raw_lines[idx].endswith("\r\n"):
                ending = "\r\n"
            elif raw_lines[idx].endswith("\n"):
                ending = "\n"
            raw_lines[idx] = fx.after + ending
            changed = True

        if changed:
            with open(abspath, "w", encoding="utf-8", newline="") as fh:
                fh.writelines(raw_lines)
            modified.append(relpath)
    return modified
