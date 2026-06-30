"""MCP005 — secrets committed into MCP / Claude config.

MCP servers are often configured with `env` blocks that people fill in with real
keys and then commit. We flag high-confidence token shapes and obvious
KEY=secret assignments in config and manifest files.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo
from .base import Rule, register

# (label, pattern) — high-signal token formats.
TOKEN_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# Generic KEY = "value" assignments where the name screams secret.
ASSIGN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)\b"
    r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)
# Obvious placeholders we should NOT flag.
PLACEHOLDER = re.compile(
    r"(?i)\b(your|example|changeme|placeholder|xxx+|<[^>]+>|\.\.\.|todo|dummy|test[_-]?key)\b"
    r"|^\$\{|^\{\{"
)


@register
class LeakedSecrets(Rule):
    id = "MCP005"
    name = "Leaked secret in config"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if f.kind not in ("config", "manifest", "source"):
                continue
            for i, line in enumerate(f.lines, start=1):
                for label, pat in TOKEN_PATTERNS:
                    if pat.search(line):
                        out.append(self.finding(
                            f, i, self._redact(line),
                            title=f"Committed secret: {label}",
                            detail="Rotate this credential and load it from the environment "
                                   "instead of committing it.",
                            severity=Severity.CRITICAL,
                        ))
                        break
                else:
                    m = ASSIGN.search(line)
                    if m and not PLACEHOLDER.search(m.group(2)):
                        out.append(self.finding(
                            f, i, self._redact(line),
                            title=f"Hardcoded secret in '{m.group(1)}'",
                            detail="Looks like a real credential assigned inline. Move it to an "
                                   "env var / secret store.",
                        ))
        return out

    @staticmethod
    def _redact(line: str) -> str:
        # Keep enough to locate, hide the secret body.
        def hide(m: "re.Match") -> str:
            s = m.group(0)
            return s[:6] + "…REDACTED…" + s[-2:] if len(s) > 12 else "…REDACTED…"
        for _, pat in TOKEN_PATTERNS:
            line = pat.sub(hide, line)
        return line
