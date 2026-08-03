"""MCP022 — a server bound to loopback only still accepts cross-origin
requests, because it never checks the `Origin` header.

Binding to `127.0.0.1`/`localhost` is often treated as equivalent to
"unreachable by web content." It isn't: any browser tab open on the same
machine can still reach a loopback-bound HTTP or WebSocket server via CORS
or an unauthenticated WebSocket upgrade, unless the server explicitly
checks the `Origin` header. This exact pattern has now surfaced three times
independently: Ollama's long-known default-CORS behavior, BraveMCP's own
HTTP bridge before it was fixed 2026-07-13 (v0.2.0) — its own release notes
at the time called the bug out as generalizing to "a lot of local-AI-tool
bridges," not just BraveMCP — and Cline's Hub dashboard WebSocket, still
open today, which accepts unauthenticated `desktopCommand` frames from any
page open in the same browser when its `ROOM_SECRET` is left at its empty
default. See `research/2026-08-03.md`'s top compounding opportunity.

Two co-occurring conditions in the same file, both required:

1. A bind call explicitly scoped to loopback only (`127.0.0.1` or
   `localhost`) — the "looks safe" case MCP018 (bind-*all*) doesn't cover.
2. Either:
   - a permissive CORS setup: an Express/Connect `cors()` call with no
     options argument, a bare Flask-CORS `CORS(app)` call with no
     `origins=`/`resources=` restriction, or an unconditional wildcard
     `Access-Control-Allow-Origin: *` header; or
   - a WebSocket connection handler (`.on('connection', ...)`) with no
     `Origin` check anywhere in the handler window.

Deliberately conservative, matching the rest of mcpscan's "high signal over
recall" design: this only fires on a server that is explicitly, visibly
loopback-bound (not bind-all — that's MCP018) and demonstrably skips the
one check that actually matters for a same-machine browser tab.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

_SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}
_JS_EXTS = {".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}

# A bind call explicitly scoped to loopback only.
_LOOPBACK_BIND_RE = re.compile(
    r"host['\"]?\s*[:=]\s*['\"](?:127\.0\.0\.1|localhost)['\"]"  # Flask/uvicorn host=, JS {host: ...}
    r"|\.listen\s*\(\s*[\w.]+\s*,\s*['\"](?:127\.0\.0\.1|localhost)['\"]"  # Node .listen(port, host)
    r"|serve\s*\(\s*[\w.]+\s*,\s*['\"](?:127\.0\.0\.1|localhost)['\"]"     # Python websockets.serve(handler, host, ...)
)

# A permissive CORS setup with no origin restriction at all.
_PERMISSIVE_CORS_RE = re.compile(
    r"\bcors\s*\(\s*\)"                                        # Express cors() — defaults to '*'
    r"|\bCORS\s*\(\s*\w+\s*\)"                                  # Flask-CORS CORS(app) bare
    r"|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]"  # literal wildcard header
)

# A WebSocket connection handler registration (JS ecosystem: ws, socket.io, uWebSockets...).
_WS_CONNECTION_RE = re.compile(r"\.on\s*\(\s*['\"]connection['\"]")

# Anything in the handler window that looks like it inspects the Origin header.
_ORIGIN_CHECK_RE = re.compile(r"origin", re.IGNORECASE)

_WINDOW = 20


@register
class LoopbackBridgeNoOriginCheck(Rule):
    id = "MCP022"
    name = "Loopback-bound server accepts cross-origin requests with no Origin check"
    severity = Severity.HIGH
    owasp = "MCP07:2025"  # Insufficient Authentication & Authorization

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source", "manifest"):
            if f.ext not in _SOURCE_EXTS:
                continue
            if not _LOOPBACK_BIND_RE.search(f.text):
                continue

            lines = f.lines

            for i, line in enumerate(lines, start=1):
                if _PERMISSIVE_CORS_RE.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Loopback-bound server has a permissive CORS setup",
                        detail=(
                            "This server binds to 127.0.0.1/localhost only, which is "
                            "commonly (wrongly) treated as 'unreachable from the web'. "
                            "Any browser tab open on the same machine can still reach it "
                            "unless the Origin header is checked — this is the exact bug "
                            "class BraveMCP's own HTTP bridge shipped and fixed in v0.2.0 "
                            "(2026-07-13), and that Cline's Hub dashboard currently has "
                            "open. Restrict allowed origins explicitly instead of "
                            "defaulting to '*'."
                        ),
                    ))

            if f.ext in _JS_EXTS:
                n = len(lines)
                for i, line in enumerate(lines):
                    if not _WS_CONNECTION_RE.search(line):
                        continue
                    window_text = "\n".join(lines[i:min(i + _WINDOW, n)])
                    if _ORIGIN_CHECK_RE.search(window_text):
                        continue
                    out.append(self.finding(
                        f, i + 1, line,
                        title="Loopback-bound WebSocket accepts connections with no Origin check",
                        detail=(
                            "This WebSocket server binds to 127.0.0.1/localhost only, but "
                            "the connection handler never checks the Origin header before "
                            "accepting the upgrade. Any page open in the same browser can "
                            "connect and send frames — the same gap behind Cline's "
                            "currently-open Hub dashboard bug, where an unset ROOM_SECRET "
                            "lets any local webpage send desktopCommand frames. Validate "
                            "the Origin header (or an equivalent per-connection secret) "
                            "before accepting the upgrade."
                        ),
                    ))
        return out
