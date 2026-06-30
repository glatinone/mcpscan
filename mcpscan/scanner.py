"""Orchestration: discover files, run every registered rule, aggregate a Report."""

from __future__ import annotations

from .findings import Report
from .loaders import discover_files
from .suppress import is_suppressed, load_ignore_patterns, path_ignored
from . import rules as rules_pkg


def scan(root: str) -> Report:
    ignore_patterns = load_ignore_patterns(root)
    files = [f for f in discover_files(root)
             if not path_ignored(f.relpath, ignore_patterns)]

    report = Report(root=root, files_scanned=len(files))
    lines_by_path = {f.relpath: f.lines for f in files}

    for rule in rules_pkg.all_rules():
        try:
            for finding in rule.check(files):
                if is_suppressed(finding, lines_by_path):
                    report.suppressed += 1
                else:
                    report.add(finding)
        except Exception as exc:  # a buggy rule shouldn't kill the whole scan
            report.errors.append(f"{rule.id} failed: {exc}")
    return report
