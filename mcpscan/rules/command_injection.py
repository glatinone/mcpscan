"""MCP001 — command injection sinks in MCP server source.

~43% of MCP CVEs in early 2026 were command-injection patterns. We flag shell
execution that is reachable from tool handlers, prioritising calls that look like
they interpolate untrusted input.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# Python sinks that ALWAYS spawn a shell, so a built command string is injectable.
PY_SINKS = re.compile(r"\b(os\.system|os\.popen)\b", re.IGNORECASE)
# subprocess.* is only injectable when shell=True (otherwise the argv is literal).
PY_SHELL_TRUE = re.compile(r"shell\s*=\s*True")

# Node/TS sinks.
JS_SINKS = re.compile(
    r"\b(child_process\.)?(execSync|exec|spawnSync|spawn)\s*\(",
)

# Heuristic that the command string is dynamically built (interpolation /
# concatenation / f-string) rather than a constant literal.
INTERP = re.compile(r"`[^`]*\$\{|\+\s*\w|%\s*\(|\.format\(|f['\"]|\$\{")

# eval-family — always suspicious in a tool handler.
EVAL = re.compile(r"\beval\s*\(|\bexec\s*\(|\bFunction\s*\(")


@register
class CommandInjection(Rule):
    id = "MCP001"
    name = "Potential command injection"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out = []
        for f in by_kind(files, "source", "manifest"):
            if f.ext not in {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}:
                continue
            is_py = f.ext == ".py"
            for i, line in enumerate(f.lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                hit = None
                sev = self.severity

                if is_py and PY_SHELL_TRUE.search(line):
                    hit = "subprocess called with shell=True"
                    sev = Severity.CRITICAL if INTERP.search(line) else Severity.HIGH
                elif is_py and PY_SINKS.search(line):
                    hit = "shell execution sink"
                    sev = Severity.CRITICAL if INTERP.search(line) else Severity.MEDIUM
                elif not is_py and JS_SINKS.search(line):
                    hit = "child process execution"
                    sev = Severity.CRITICAL if INTERP.search(line) else Severity.MEDIUM
                elif EVAL.search(line):
                    hit = "dynamic code execution (eval/exec)"
                    sev = Severity.HIGH

                if hit:
                    out.append(self.finding(
                        f, i, line,
                        title=f"Command injection risk: {hit}",
                        detail="Tool handlers that shell out with interpolated input let a "
                               "crafted argument run arbitrary commands. Use argument "
                               "lists (no shell=True), validate inputs, or avoid eval.",
                        severity=sev,
                    ))
        return out
