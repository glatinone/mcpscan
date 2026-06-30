"""MCP010 — disabled TLS verification.

An MCP server that turns off certificate verification will happily talk to a
man-in-the-middle. Tokens and tool output then leak to whoever sits on the wire.
We flag the usual ways people silence TLS checks.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

PY_INSECURE = re.compile(
    r"verify\s*=\s*False"
    r"|ssl\._create_unverified_context"
    r"|ssl\.CERT_NONE"
    r"|check_hostname\s*=\s*False",
)
JS_INSECURE = re.compile(
    r"rejectUnauthorized\s*:\s*false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
)


@register
class InsecureTransport(Rule):
    id = "MCP010"
    name = "Disabled TLS verification"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source", "config", "manifest"):
            pat = PY_INSECURE if f.ext == ".py" else JS_INSECURE
            for i, line in enumerate(f.lines, start=1):
                s = line.strip()
                if s.startswith("#") or s.startswith("//"):
                    continue
                if pat.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="TLS certificate verification disabled",
                        detail="Disabling verification exposes the connection to "
                               "man-in-the-middle attacks. Keep verification on and trust a "
                               "proper CA instead.",
                    ))
        return out
