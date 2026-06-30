"""MCP003 — dangerous hooks in Claude Code projects.

`.claude/settings.json` (and friends) can register hooks that run shell commands
automatically on events like PreToolUse / PostToolUse. A malicious repo can ship a
hook that fires the moment you open it. We flag the classic remote-exec and
exfiltration shapes.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo
from .base import Rule, register

# curl/wget piped straight into a shell — remote code execution.
REMOTE_EXEC = re.compile(
    r"(?:curl|wget|iwr|Invoke-WebRequest)\b[^|;\n]*\|\s*(?:ba)?sh\b"
    r"|(?:curl|wget)\b[^|;\n]*\|\s*(?:python|node|perl)\b",
    re.IGNORECASE,
)
# base64 -d | sh and friends.
OBFUSCATED = re.compile(r"base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh|eval\s*\(?\s*atob", re.IGNORECASE)
# Reading env/secrets and shipping them somewhere.
EXFIL = re.compile(
    r"(?:env|printenv|cat\s+[^|;\n]*\.env|echo\s+\$[A-Z_]+)[^|;\n]*\|\s*(?:curl|wget|nc)\b"
    r"|(?:curl|wget|nc)\b[^|\n]*(?:\$[A-Z_]+|\benv\b|TOKEN|SECRET|KEY)",
    re.IGNORECASE,
)


@register
class DangerousHooks(Rule):
    id = "MCP003"
    name = "Dangerous Claude Code hook"
    severity = Severity.CRITICAL

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            # Hooks live in .claude/ settings, but a command string can hide
            # anywhere; we scan broadly and lean on the patterns themselves.
            looks_hooky = f.in_dot_claude or "hook" in f.text.lower() or f.name.endswith(".sh")
            if not looks_hooky:
                continue
            for i, line in enumerate(f.lines, start=1):
                if REMOTE_EXEC.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Hook pipes a remote payload into a shell",
                        detail="`curl … | sh` in a hook runs attacker-controlled code on the "
                               "machine of anyone who opens the project. Never auto-fetch+exec.",
                    ))
                elif OBFUSCATED.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Hook executes obfuscated (base64) payload",
                        detail="Decoding then executing a blob hides intent from review.",
                    ))
                elif EXFIL.search(line):
                    out.append(self.finding(
                        f, i, line,
                        title="Hook may exfiltrate environment/secrets",
                        detail="A hook sending env vars or tokens over the network is a "
                               "credential-theft pattern.",
                        severity=Severity.HIGH,
                    ))
        return out
