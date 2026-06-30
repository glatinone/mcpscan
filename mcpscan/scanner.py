"""Orchestration: discover files, run every registered rule, aggregate a Report."""

from __future__ import annotations

from .findings import Report
from .loaders import discover_files
from . import rules as rules_pkg


def scan(root: str) -> Report:
    files = discover_files(root)
    report = Report(root=root, files_scanned=len(files))
    for rule in rules_pkg.all_rules():
        try:
            report.extend(rule.check(files))
        except Exception as exc:  # a buggy rule shouldn't kill the whole scan
            report.errors.append(f"{rule.id} failed: {exc}")
    return report
