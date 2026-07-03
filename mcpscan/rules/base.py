"""Rule base class, a registry, and shared regex-scanning helpers."""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Pattern, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo

# Populated by @register; the scanner iterates over this.
REGISTRY: "List[Rule]" = []


class Rule:
    """A single detector. Subclasses implement :meth:`check`."""

    id: str = "MCP000"
    name: str = "unnamed rule"
    severity: Severity = Severity.MEDIUM

    def check(self, files: List[FileInfo]) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError

    def fix_line(self, line: str) -> Optional[Tuple[str, str]]:
        """Return `(fixed_line, explanation)` if *line* can be mechanically repaired.

        Default: not fixable. Only override this for a substitution confident
        enough that it can't be the wrong call — e.g. swapping `yaml.load` for
        `yaml.safe_load`. Fixes that require choosing new argument values or
        restructuring a call (like turning a shell string into an argv list for
        `shell=True`) belong in a human's hands, not `--fix`.
        """
        return None

    # --- helpers shared by most rules -------------------------------------

    def finding(self, f: FileInfo, line: int, snippet: str, *,
                title: str = "", detail: str = "",
                severity: "Severity | None" = None) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title or self.name,
            severity=severity or self.severity,
            path=f.relpath,
            line=line,
            detail=detail,
            snippet=snippet.strip()[:200],
        )

    def scan_lines(self, f: FileInfo, pattern: Pattern[str], *,
                   title: str = "", detail: str = "",
                   severity: "Severity | None" = None,
                   predicate: "Callable[[re.Match], bool] | None" = None
                   ) -> List[Finding]:
        """Yield a finding for every line in *f* matching *pattern*."""
        out: List[Finding] = []
        for i, line in enumerate(f.lines, start=1):
            m = pattern.search(line)
            if not m:
                continue
            if predicate and not predicate(m):
                continue
            out.append(self.finding(f, i, line, title=title,
                                     detail=detail, severity=severity))
        return out


def register(cls):
    """Class decorator that adds a rule instance to the registry."""
    REGISTRY.append(cls())
    return cls


def compile_any(*patterns: str, flags: int = re.IGNORECASE) -> Pattern[str]:
    """Compile an alternation of patterns into one regex."""
    return re.compile("|".join(f"(?:{p})" for p in patterns), flags)


def deny_block_lines(lines: List[str]) -> "set[int]":
    """Return the 1-based line numbers that fall inside a `"deny": [...]` array.

    Tracks bracket depth from the `"deny"` key onward so multi-line deny lists
    are fully covered, not just the one or two lines after the key. Wildcards
    that a config explicitly *denies* are good practice, not a finding.
    """
    out: "set[int]" = set()
    active = False
    depth = 0
    for i, line in enumerate(lines, start=1):
        if not active and '"deny"' in line.lower():
            active = True
            depth = 0
        if not active:
            continue
        depth += line.count("[") - line.count("]")
        out.add(i)
        if depth <= 0:
            active = False
    return out
