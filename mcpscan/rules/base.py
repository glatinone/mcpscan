"""Rule base class, a registry, and shared regex-scanning helpers."""

from __future__ import annotations

import re
from typing import Callable, List, Pattern

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
