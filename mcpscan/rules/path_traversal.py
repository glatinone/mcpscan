"""MCP007 — path traversal in file-reading tools.

A tool that opens a path built from its arguments lets a caller walk out of the
intended directory (``../../etc/passwd``) and read arbitrary files. We flag file
reads whose path is interpolated/concatenated rather than a constant literal.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# File-open sinks.
PY_OPEN = re.compile(
    r"\bopen\s*\(|\.read_text\s*\(|\.read_bytes\s*\(|send_file\s*\(|FileResponse\s*\(",
)
JS_OPEN = re.compile(
    r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(|\breadFile(?:Sync)?\s*\(",
)
# Path is dynamically built (concat / f-string / template / join with a var).
INTERP = re.compile(r"`[^`]*\$\{|\+\s*\w|f['\"]|\.format\(|os\.path\.join\([^)]*\b\w")
# Explicit traversal token sitting in a literal.
TRAVERSAL = re.compile(r"\.\./|\.\.\\")


@register
class PathTraversal(Rule):
    id = "MCP007"
    name = "Path traversal in file tool"
    severity = Severity.MEDIUM
    owasp = "MCP05:2025"  # Command Injection & Execution (untrusted-input-driven action)

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source"):
            is_py = f.ext == ".py"
            sink = PY_OPEN if is_py else JS_OPEN
            for i, line in enumerate(f.lines, start=1):
                s = line.strip()
                if s.startswith("#") or s.startswith("//"):
                    continue
                if not sink.search(line):
                    continue
                if INTERP.search(line):
                    sev = Severity.HIGH if TRAVERSAL.search(line) else Severity.MEDIUM
                    out.append(self.finding(
                        f, i, line,
                        title="File path built from untrusted input",
                        detail="Resolve the path and confirm it stays within an allowed base "
                               "directory (e.g. os.path.realpath + prefix check) before opening.",
                        severity=sev,
                    ))
        return out
