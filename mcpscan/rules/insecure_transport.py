"""MCP010 — disabled TLS verification.

An MCP server that turns off certificate verification will happily talk to a
man-in-the-middle. Tokens and tool output then leak to whoever sits on the wire.
We flag the usual ways people silence TLS checks.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

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

# --- fix_line helpers -------------------------------------------------------
# Each of these is a bare value/name swap with no argument restructuring, so
# it can't change what the surrounding call actually does besides re-enabling
# the check that was turned off.
_UNVERIFIED_CTX = re.compile(r"ssl\._create_unverified_context\s*\(\s*\)")
_CERT_NONE = re.compile(r"\bssl\.CERT_NONE\b")
_REJECT_UNAUTH_FALSE = re.compile(r"rejectUnauthorized\s*:\s*false")
_NODE_TLS_ENV = re.compile(r"(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*)(['\"]?)0\2")


def _drop_false_kwarg(line: str, name: str) -> Optional[str]:
    """Remove a `, name=False` / `name=False, ` / bare `name=False` kwarg.

    Tries the leading-comma form first since the disabled check is rarely the
    first argument in a real call (e.g. `requests.get(url, verify=False)`).
    """
    patterns = [
        rf"\s*,\s*{name}\s*=\s*False\b",
        rf"\b{name}\s*=\s*False\s*,\s*",
        rf"\b{name}\s*=\s*False\b",
    ]
    for pat in patterns:
        fixed, n = re.subn(pat, "", line, count=1)
        if n:
            return fixed
    return None


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

    def fix_line(self, line: str) -> Optional[Tuple[str, str]]:
        if _UNVERIFIED_CTX.search(line):
            fixed = _UNVERIFIED_CTX.sub("ssl.create_default_context()", line)
            return fixed, ("create_default_context() verifies certificates against the "
                            "system trust store instead of accepting anything.")
        if _CERT_NONE.search(line):
            fixed = _CERT_NONE.sub("ssl.CERT_REQUIRED", line)
            return fixed, "CERT_REQUIRED makes the handshake fail on an invalid certificate."
        if _REJECT_UNAUTH_FALSE.search(line):
            fixed = _REJECT_UNAUTH_FALSE.sub("rejectUnauthorized: true", line)
            return fixed, "rejectUnauthorized: true restores certificate validation."
        if _NODE_TLS_ENV.search(line):
            fixed = _NODE_TLS_ENV.sub(lambda m: f"{m.group(1)}{m.group(2)}1{m.group(2)}", line)
            return fixed, ("NODE_TLS_REJECT_UNAUTHORIZED=1 is the default, safe setting; "
                            "=0 disables TLS verification for the whole process.")
        fixed = _drop_false_kwarg(line, "verify")
        if fixed is not None:
            return fixed, "Dropping verify=False restores the library default (verify=True)."
        fixed = _drop_false_kwarg(line, "check_hostname")
        if fixed is not None:
            return fixed, ("Dropping check_hostname=False restores hostname verification "
                            "(the default).")
        return None
