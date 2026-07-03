"""MCP012 — remote MCP servers with no authentication or a hardcoded static token.

Remote (HTTP/SSE) MCP server entries are reachable over the network, so they need
some credential to stop anyone who can reach the URL from calling their tools.
Two patterns get flagged:

1. A remote server entry with no auth-bearing header/field at all.
2. A bearer token or API key hardcoded as a literal string in a header instead
   of being pulled from the environment (`${TOKEN}` / `$TOKEN`).

Local, command/stdio-launched servers are out of scope — they inherit the
caller's own OS-level permissions and don't need a network credential.

2026 field data puts no-auth and static-token MCP deployments at 60-90% of
real installs, well ahead of tool-poisoning-style findings — see
`research/2026-07-03.md`.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, List, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo
from .base import Rule, register

_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers")
_URL_KEYS = ("url", "serverUrl", "endpoint")
_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token"}

# A value that's an environment reference, not a literal secret.
ENV_INTERPOLATION = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")
# Looks like a real token/key rather than a short placeholder word.
STATIC_TOKEN_SHAPE = re.compile(r"^(Bearer\s+)?[A-Za-z0-9_\-.]{16,}$")


def _iter_server_entries(data: Any) -> Iterator[Tuple[str, Dict]]:
    if not isinstance(data, dict):
        return
    for key in _SERVER_KEYS:
        servers = data.get(key)
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    yield name, cfg


@register
class AuthGaps(Rule):
    id = "MCP012"
    name = "MCP server with no auth or a hardcoded static token"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if f.ext != ".json":
                continue
            try:
                data = json.loads(f.text)
            except (ValueError, TypeError):
                continue

            for name, cfg in _iter_server_entries(data):
                url = next((cfg.get(k) for k in _URL_KEYS if isinstance(cfg.get(k), str)), None)
                if not url or not url.startswith(("http://", "https://")):
                    continue  # local/stdio server: not this rule's concern

                headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
                auth_value = next(
                    (v for k, v in headers.items() if k.lower() in _AUTH_HEADER_NAMES), None
                )
                line = self._line_for(f, name)

                if auth_value is None:
                    out.append(self.finding(
                        f, line, f'"{name}": {{"url": "{url}"}}',
                        title=f"Remote MCP server '{name}' has no authentication",
                        detail="This server is reachable over the network with no "
                               "Authorization / API-key header configured — anyone who can "
                               "reach the URL can call its tools.",
                    ))
                elif (isinstance(auth_value, str)
                        and not ENV_INTERPOLATION.match(auth_value.strip())
                        and STATIC_TOKEN_SHAPE.match(auth_value.strip())):
                    out.append(self.finding(
                        f, line, f'"{name}" auth header hardcodes a literal token',
                        title=f"Static long-lived token hardcoded for '{name}'",
                        detail="The auth header is a literal token instead of an environment "
                               "reference (e.g. ${TOKEN}) — it can't be rotated without editing "
                               "this file, and leaks if the file is shared or committed.",
                        severity=Severity.MEDIUM,
                    ))
        return out

    @staticmethod
    def _line_for(f: FileInfo, server_name: str) -> int:
        needle = f'"{server_name}"'
        for i, line in enumerate(f.lines, start=1):
            if needle in line:
                return i
        return 0
