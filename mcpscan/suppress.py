"""Suppression support: a `.mcpscanignore` file and inline ignore comments.

Inline markers (on the finding's line or the line directly above):

    risky_call(x)            # mcpscan: ignore           -> suppress every rule here
    risky_call(x)            # mcpscan: ignore[MCP001]   -> suppress only MCP001
    risky_call(x)            // mcpscan: ignore[MCP001,MCP005]

`.mcpscanignore` (repo root) holds gitignore-style globs, one per line; matching
files are never scanned. Blank lines and `#` comments are ignored.
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Dict, List, Optional

from .findings import Finding

IGNORE_FILE = ".mcpscanignore"

_MARKER = re.compile(r"mcpscan:\s*ignore(?:\[([A-Za-z0-9_,\s]+)\])?", re.IGNORECASE)


def load_ignore_patterns(root: str) -> List[str]:
    path = os.path.join(root, IGNORE_FILE)
    patterns: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.rstrip("/"))
    except OSError:
        pass
    return patterns


def path_ignored(relpath: str, patterns: List[str]) -> bool:
    rel = relpath.replace(os.sep, "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
            return True
        # bare name like "secrets.json" should match anywhere in the tree
        if "/" not in pat and fnmatch.fnmatch(os.path.basename(rel), pat):
            return True
    return False


def _line_suppresses(line: str, rule_id: str) -> bool:
    m = _MARKER.search(line)
    if not m:
        return False
    ids = m.group(1)
    if not ids:
        return True  # bare ignore -> all rules
    wanted = {x.strip().upper() for x in ids.split(",") if x.strip()}
    return rule_id.upper() in wanted


def is_suppressed(finding: Finding, lines_by_path: Dict[str, List[str]]) -> bool:
    lines: Optional[List[str]] = lines_by_path.get(finding.path)
    if not lines or finding.line <= 0:
        return False
    idx = finding.line - 1  # 0-based
    candidates = [idx]
    if idx - 1 >= 0:
        candidates.append(idx - 1)  # marker on the line above
    for i in candidates:
        if 0 <= i < len(lines) and _line_suppresses(lines[i], finding.rule_id):
            return True
    return False
