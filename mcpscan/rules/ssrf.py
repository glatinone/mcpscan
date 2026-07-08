"""MCP008 — server-side request forgery (SSRF) in fetch tools.

A tool that fetches a URL assembled from its arguments can be steered at internal
metadata endpoints (169.254.169.254), localhost services, or arbitrary hosts. We
flag outbound HTTP calls whose URL is interpolated from input.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

PY_FETCH = re.compile(
    r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\("
    r"|\burllib\.request\.urlopen\s*\("
    r"|\bhttpx\.(?:get|post|put|patch|delete|stream|Client)\s*\("
    r"|\baiohttp\b[^\n]*\.(?:get|post|request)\s*\(",
)
JS_FETCH = re.compile(
    r"\bfetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|request))?\s*\("
    r"|\b(?:https?)\.(?:get|request)\s*\(|\bgot\s*\(",
)
INTERP = re.compile(r"`[^`]*\$\{|\+\s*\w|f['\"]|\.format\(|%\s*\(")
# A literal-looking URL argument (constant) is much lower risk.
HAS_INTERP_URL = re.compile(r"\(\s*(?:f?['\"`])?[^)]*(?:\$\{|\+\s*\w|f['\"]|\{\})")


@register
class SSRF(Rule):
    id = "MCP008"
    name = "SSRF in fetch tool"
    severity = Severity.MEDIUM
    owasp = "MCP05:2025"  # Command Injection & Execution (untrusted-input-driven action)

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source"):
            is_py = f.ext == ".py"
            sink = PY_FETCH if is_py else JS_FETCH
            for i, line in enumerate(f.lines, start=1):
                s = line.strip()
                if s.startswith("#") or s.startswith("//"):
                    continue
                if sink.search(line) and INTERP.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Outbound request to a URL built from input",
                        detail="Validate the host against an allowlist and block link-local / "
                               "private ranges (169.254.169.254, 127.0.0.0/8, 10/8) to prevent "
                               "SSRF against cloud metadata and internal services.",
                        severity=Severity.HIGH if "169.254" in line else Severity.MEDIUM,
                    ))
        return out
