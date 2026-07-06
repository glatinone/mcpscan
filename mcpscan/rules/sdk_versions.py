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
# Audited 2026-07-06 against the GitHub Advisory Database — each baseline is the
# highest first-patched version among that package's disclosed CVEs, so a version
# below it may still carry an earlier, already-superseded advisory too.
KNOWN_BAD = {
    # CVE-2026-25536 (GHSA-345p-7cg4-v4c7): cross-client data leak via shared
    # transport/server reuse, patched 1.26.0. Supersedes the 1.12.0 stdio RCE
    # baseline and the 1.25.2 ReDoS fix (CVE-2026-0621).
    "@modelcontextprotocol/sdk": (
        "1.26.0",
        "CVE-2026-25536: cross-client data leak via shared transport/server reuse "
        "(also fixes the CVE-2026-0621 UriTemplate ReDoS)",
    ),
    # CVE-2025-66416 (GHSA-9h52-p55h-vw2f): no DNS-rebinding protection by
    # default on localhost HTTP servers, patched 1.23.0. Supersedes the 1.9.0
    # message-handling RCE baseline and the 1.9.4 malformed-request DoS fix
    # (CVE-2025-53366).
    "mcp": (
        "1.23.0",
        "CVE-2025-66416: no DNS-rebinding protection by default for localhost "
        "HTTP servers (also fixes the CVE-2025-53366 malformed-request DoS)",
    ),
    # GHSA-vv7q-7jx5-f767 (critical, CVSS 10.0): OpenAPIProvider path params
    # substituted into URLs unescaped, allowing path traversal out of the
    # intended API prefix (authenticated SSRF). Patched 3.2.0, alongside the
    # OAuth confused-deputy (CVE-2026-27124) and Windows install command
    # injection (GHSA-m8x7-r2rg-vh5g) advisories in the same release line.
    # Supersedes the 2.3.0 tool-dispatch baseline and the 2.14.2 OAuth
    # token-audience fix (CVE-2025-69196).
    "fastmcp": (
        "3.2.0",
        "GHSA-vv7q-7jx5-f767: unescaped path params in OpenAPIProvider enable "
        "path traversal / authenticated SSRF (also fixes the CVE-2026-27124 OAuth "
        "confused-deputy and GHSA-m8x7-r2rg-vh5g Windows install command injection)",
    ),
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
