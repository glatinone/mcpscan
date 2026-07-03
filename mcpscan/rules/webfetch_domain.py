"""MCP011 — over-broad WebFetch domain allowances.

Claude Code / MCP permission configs can scope the WebFetch tool to specific
hosts with `WebFetch(domain:example.com)`. That scoping is meaningless if the
domain itself is a wildcard, a bare top-level-domain wildcard (`*.com`), or
missing entirely (a bare `"WebFetch"` allow-entry) — any of these let the
agent fetch, and exfiltrate data to, an attacker-controlled host.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, deny_block_lines, register

# WebFetch(domain:*) — the domain filter is itself a wildcard.
WILDCARD_DOMAIN = re.compile(r'WebFetch\s*\(\s*domain\s*:\s*\*\s*\)', re.IGNORECASE)
# WebFetch(domain:*.com) / (*.io) / (*.dev) — a bare-TLD wildcard covers every
# domain under that TLD, which is not a meaningful restriction.
BROAD_TLD_DOMAIN = re.compile(r'WebFetch\s*\(\s*domain\s*:\s*\*\.[a-z0-9-]+\s*\)', re.IGNORECASE)
# A bare "WebFetch" allow-entry with no domain scoping at all.
BARE_WEBFETCH = re.compile(r'^"\s*WebFetch\s*"\s*,?\s*$')


@register
class OverBroadWebFetchDomain(Rule):
    id = "MCP011"
    name = "Over-broad WebFetch domain allowance"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        candidates = [f for f in by_kind(files, "config", "manifest")
                      if f.in_dot_claude or "webfetch" in f.text.lower()]
        for f in candidates:
            deny_lines = deny_block_lines(f.lines)
            for i, line in enumerate(f.lines, start=1):
                if i in deny_lines:
                    continue  # wildcards inside deny[] are fine

                if WILDCARD_DOMAIN.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="WebFetch allowed for any domain",
                        detail="WebFetch(domain:*) removes the domain restriction entirely — "
                               "the agent can fetch from, and exfiltrate data to, any host.",
                    ))
                elif BROAD_TLD_DOMAIN.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="WebFetch scoped to a whole top-level domain",
                        detail="A bare TLD wildcard (e.g. *.com) covers millions of domains — "
                               "scope WebFetch to the specific host(s) the tool actually needs.",
                        severity=Severity.MEDIUM,
                    ))
                elif BARE_WEBFETCH.match(line.strip()):
                    out.append(self.finding(
                        f, i, line,
                        title="WebFetch allowed with no domain filter",
                        detail="A bare \"WebFetch\" allow-entry has no domain argument — "
                               "equivalent to WebFetch(domain:*).",
                    ))
        return out
