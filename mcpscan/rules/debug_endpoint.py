"""MCP018 — a debug/proxy/inspector server bound to all interfaces exposes an
unauthenticated connect/exec-style endpoint.

This exact vulnerability shape has now been independently confirmed twice in
the MCP tooling ecosystem itself: Anthropic's own MCP Inspector
(CVE-2025-49596, CVSS 9.4) and MCPJam Inspector (CVE-2026-23744, CVSS 9.8, no
user interaction required) both bound their HTTP proxy to every network
interface instead of localhost and exposed a connect-style endpoint that
accepted a raw command/args payload with no authentication — achieving remote
code execution from a single crafted request. Two unrelated teams building
tools in mcpscan's exact target domain made the identical insecure-default
mistake roughly eight months apart. See `research/2026-07-17.md`'s top
compounding opportunity.

Two co-occurring conditions in the same file, both required:

1. A server bind call that exposes the process to every network interface,
   not just localhost — an explicit all-interfaces host (`0.0.0.0`, `::`, or
   an empty host string), or a Node `.listen(port)` call with no host
   argument at all (which defaults to all interfaces).
2. A route/handler whose path looks like a debug/inspector connect-or-exec
   endpoint, which spawns a process using a command/args value read straight
   out of the request body, with no authentication check anywhere in the
   handler.

Deliberately conservative, matching the rest of mcpscan's "high signal over
recall" design: this only fires on the literal shape both disclosed CVEs
share (bind-all + unauthenticated request-driven process spawn on a
connect/exec-shaped route), not on every HTTP server that happens to spawn a
process anywhere in the file.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

_SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}

# A bind call exposing the process to every network interface.
_BIND_ALL_RE = re.compile(
    r"host\s*=\s*['\"](?:0\.0\.0\.0|::|)['\"]"          # Flask/uvicorn/FastAPI host=
    r"|HTTPServer\s*\(\s*\(\s*['\"]['\"]\s*,"           # Python http.server (('', port))
    r"|\.listen\s*\(\s*[\w.]+\s*,\s*['\"]0\.0\.0\.0['\"]"  # Node .listen(port, '0.0.0.0')
    r"|\.listen\s*\(\s*[\w.]+\s*\)"                     # Node .listen(port) — no host, defaults all
)

# An HTTP route/handler registration.
_ROUTE_CALL_RE = re.compile(
    r"@\w+\.route\s*\(|\.(?:get|post|put|all|route)\s*\(|app\.(?:get|post|put|all)\s*\("
)
# ...whose path string looks like a debug/inspector connect-or-exec endpoint.
_CONNECT_PATH_RE = re.compile(
    r"['\"][^'\"]*(?:connect|exec|spawn)[^'\"]*['\"]", re.IGNORECASE
)

# The handler parses the request body somewhere in the window...
_REQUEST_BODY_RE = re.compile(
    r"req\.body|request\.json|ctx\.request\.body|request\.get_json\(\)",
    re.IGNORECASE,
)
# ...and a spawn call is given a command/args-shaped field access as an
# argument (parsed body -> variable -> field access is the common real-world
# shape, not necessarily the same line as the parse call itself).
_SPAWN_CALL_RE = re.compile(
    r"\b(?:spawn|spawnSync|exec|execSync|subprocess\.(?:run|Popen|call))\s*\("
)
_COMMAND_FIELD_ACCESS_RE = re.compile(
    r"\[['\"]?(?:command|cmd|args)['\"]?\]"
    r"|\.(?:command|cmd|args)\b"
    r"|\.get\(['\"](?:command|cmd|args)['\"]",
    re.IGNORECASE,
)

# Anything in the handler window that looks like an auth check.
_AUTH_CHECK_RE = re.compile(
    r"authoriz|authenticat|api[_-]?key|bearer|verify.?token|require.?auth",
    re.IGNORECASE,
)

_WINDOW = 30


@register
class UnauthenticatedConnectExecEndpoint(Rule):
    id = "MCP018"
    name = ("Debug/proxy server bound to all interfaces exposes an "
            "unauthenticated connect/exec endpoint")
    severity = Severity.CRITICAL
    owasp = "MCP07:2025"  # Insufficient Authentication & Authorization

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source", "manifest"):
            if f.ext not in _SOURCE_EXTS:
                continue
            lines = f.lines
            if not _BIND_ALL_RE.search(f.text):
                continue

            n = len(lines)
            for i, line in enumerate(lines):
                if not (_ROUTE_CALL_RE.search(line) and _CONNECT_PATH_RE.search(line)):
                    continue

                window = lines[i:min(i + _WINDOW, n)]
                window_text = "\n".join(window)
                if _AUTH_CHECK_RE.search(window_text):
                    continue
                if not _REQUEST_BODY_RE.search(window_text):
                    continue

                spawn_idx = None
                for j, wline in enumerate(window):
                    if _SPAWN_CALL_RE.search(wline) and _COMMAND_FIELD_ACCESS_RE.search(wline):
                        spawn_idx = i + j
                        break
                if spawn_idx is None:
                    continue

                out.append(self.finding(
                    f, spawn_idx + 1, lines[spawn_idx],
                    title="Unauthenticated connect/exec endpoint on a server "
                          "bound to all interfaces",
                    detail=(
                        "This server binds to every network interface (not just "
                        "localhost) and exposes a connect/exec-style endpoint "
                        "that spawns a process using a command/args value taken "
                        "directly from the request body, with no authentication "
                        "check in the handler. This is the exact shape behind "
                        "Anthropic's own MCP Inspector RCE (CVE-2025-49596, "
                        "CVSS 9.4) and MCPJam Inspector (CVE-2026-23744, CVSS "
                        "9.8) — any host that can reach this port can run "
                        "arbitrary commands. Bind to 127.0.0.1/localhost only, "
                        "and require an authentication token before accepting a "
                        "command payload."
                    ),
                ))
        return out
