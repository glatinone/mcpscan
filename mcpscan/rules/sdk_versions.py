"""MCP006 — known-vulnerable MCP SDK versions.

A systemic RCE was disclosed across MCP SDK implementations in 2026. This rule
reads dependency declarations and flags SDK versions below the patched baseline.
It deliberately uses a small, conservative table — extend `KNOWN_BAD` as advisories
land.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# package name -> (first patched version, advisory note)
KNOWN_BAD = {
    "@modelcontextprotocol/sdk": ("1.12.0", "RCE in stdio transport message handling"),
    "mcp": ("1.9.0", "RCE in SDK message handling"),
    "fastmcp": ("2.3.0", "input-validation bypass in tool dispatch"),
}

# Matches: "@modelcontextprotocol/sdk": "^1.4.2"   or   mcp==1.2.0   or   mcp>=1.0
DEP_LINE = re.compile(
    r'["\']?(@?[\w./-]+)["\']?\s*'
    r'(?:[:=]\s*["\']?|==|>=|~=|\^|~)\s*'
    r'[\^~>=]*\s*(\d+\.\d+(?:\.\d+)?)'
)


def _cmp(a: str, b: str) -> int:
    """Return -1/0/1 comparing dotted version strings."""
    pa = [int(x) for x in a.split(".")]
    pb = [int(x) for x in b.split(".")]
    while len(pa) < len(pb): pa.append(0)
    while len(pb) < len(pa): pb.append(0)
    return (pa > pb) - (pa < pb)


@register
class VulnerableSDK(Rule):
    id = "MCP006"
    name = "Vulnerable MCP SDK version"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "manifest", "config"):
            if f.name not in {"package.json", "pyproject.toml", "requirements.txt", "mcp.json"}:
                continue
            for i, line in enumerate(f.lines, start=1):
                m = DEP_LINE.search(line)
                if not m:
                    continue
                pkg, ver = m.group(1), m.group(2)
                info: "Tuple[str, str] | None" = KNOWN_BAD.get(pkg)
                if not info:
                    continue
                patched, note = info
                if _cmp(ver, patched) < 0:
                    out.append(self.finding(
                        f, i, line,
                        title=f"{pkg} {ver} is vulnerable (< {patched})",
                        detail=f"{note}. Upgrade to >= {patched}.",
                    ))
        return out
