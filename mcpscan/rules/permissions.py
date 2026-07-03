"""MCP004 — over-broad permissions in Claude Code / MCP configuration.

A repo can ship a `.claude/settings.json` that pre-grants sweeping permissions, so
that once you trust the project the agent can run anything without prompting. We
flag wildcard allow-rules and permission-bypassing modes.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, deny_block_lines, register

# Wildcard tool grants: Bash(*), Bash(*:*), Write(*), or a bare "*" entry.
WILDCARD_RULE = re.compile(
    r'"\s*(?:Bash|Write|Edit|WebFetch|Read)\s*\(\s*\*',
    re.IGNORECASE,
)
BARE_WILDCARD = re.compile(r'^\s*"\*"\s*,?\s*$')
# Permission bypass / auto-accept everything.
BYPASS_MODE = re.compile(
    r'"defaultMode"\s*:\s*"(?:bypassPermissions|acceptEdits)"'
    r'|dangerouslySkipPermissions\s*:\s*true'
    r'|--dangerously-skip-permissions'
    r'|"autoApprove"\s*:\s*true',
    re.IGNORECASE,
)


@register
class OverBroadPermissions(Rule):
    id = "MCP004"
    name = "Over-broad permissions"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        candidates = [f for f in by_kind(files, "config", "manifest")
                      if f.in_dot_claude or "permission" in f.text.lower()
                      or "defaultMode" in f.text or f.name.endswith(".json")]
        # Wildcards inside a "deny" block are good practice, not a finding.
        for f in candidates:
            deny_lines = deny_block_lines(f.lines)
            for i, line in enumerate(f.lines, start=1):
                if BYPASS_MODE.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Permission prompts disabled",
                        detail="bypassPermissions / acceptEdits / autoApprove lets the agent "
                               "act without asking. Shipping this in a repo is a red flag.",
                        severity=Severity.CRITICAL,
                    ))
                    continue

                if i in deny_lines:
                    continue  # wildcards inside deny[] are fine

                if WILDCARD_RULE.search(line) or BARE_WILDCARD.match(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Wildcard permission grant",
                        detail="A wildcard allow-rule (e.g. Bash(*) or \"*\") grants the agent "
                               "blanket access. Scope permissions to specific commands/paths.",
                    ))
        return out
