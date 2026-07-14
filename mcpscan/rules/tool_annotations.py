"""MCP013 — tool risk annotations missing or contradicted.

The MCP spec defines four structured boolean hints a tool can declare on itself:
`readOnlyHint`, `destructiveHint` (default true), `idempotentHint`, and
`openWorldHint` (default true). They're a stable, standardized schema field —
unlike freeform description text, they don't need prose parsing to check.

The spec's own docs are explicit that these are informational, not enforced: "an
untrusted server can claim `readOnlyHint: true` and delete your files anyway."
That framing gives two distinct, checkable failure modes:

1. **Absence** — a tool detected to call a high-risk capability (subprocess/exec,
   filesystem write/delete, outbound network, SQL) ships with none of the four
   annotation keys at all. Not proof of malice, but a real signal gap: neither an
   agent nor a human skimming a tool list has any structured cue that this tool
   can act, not just read.
2. **Contradiction** — a tool claims `readOnlyHint: true` or `destructiveHint:
   false` while its own implementation calls one of those same capability sinks.
   This is a stronger finding than absence: the tool isn't silent about risk, it's
   actively misrepresenting it.

Tool boundaries are approximated, not AST-derived (mcpscan is a zero-dependency,
regex-based scanner): a "tool definition" is a Python `@x.tool(...)` decorator, a
raw `mcp.types.Tool(name=...)` construction, or a JS/TS `registerTool(...)` /
`.tool("name", ...)` call. Everything from that line up to the next tool
definition (or a line cap, so a huge trailing file doesn't get treated as one
tool) is the "block" searched for annotations and capabilities. This misses tools
defined with unusual patterns (bare `@tool` with no parens, dynamically
registered handlers) — false negatives, not false positives, which is the safer
side to err on for a rule built on heuristic block boundaries.
"""

from __future__ import annotations

import re
from typing import Dict, List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# Where a "tool" starts. Deliberately narrow (dotted-attribute decorator, a named
# `Tool(name=...)` constructor, or a call whose first argument is a string literal)
# to avoid matching unrelated `.tool(...)` calls that have nothing to do with MCP.
TOOL_DEF = re.compile(
    r"@\w[\w.]*\.tool\s*\("
    r"|\bTool\s*\(\s*name\s*="
    r"|\bregisterTool\s*\("
    r"|\.tool\s*\(\s*['\"]"
)

# The four spec-defined hint keys — presence alone is what check (1) looks for.
ANNOTATION_KEY = re.compile(r"\b(readOnlyHint|destructiveHint|idempotentHint|openWorldHint)\b")

# A tool asserting it's safe: explicitly read-only, or explicitly non-destructive.
SAFE_CLAIM = re.compile(
    r"readOnlyHint['\"]?\s*[:=]\s*(?:True|true)"
    r"|destructiveHint['\"]?\s*[:=]\s*(?:False|false)"
)

# Capability sinks a tool handler might call. Intentionally coarse (this rule asks
# "does this tool *do* something risky", not "is this specific call exploitable" —
# that finer-grained job belongs to MCP001/007/008/009).
CAPABILITIES: Dict[str, re.Pattern] = {
    "exec": re.compile(
        r"\bos\.(?:system|popen)\b"
        r"|\bsubprocess\.\w+"
        r"|\bchild_process\b"
        r"|\b(?:execSync|spawnSync|spawn|exec)\s*\("
        r"|\beval\s*\(|\bFunction\s*\(",
        re.IGNORECASE,
    ),
    "filesystem-write": re.compile(
        r"\bopen\([^)]*['\"][wa]b?['\"]"
        r"|\bfs\.(?:writeFile\w*|unlink\w*|rm\w*|appendFile\w*)"
        r"|\bos\.(?:remove|unlink|rmdir)\b"
        r"|\bshutil\.(?:rmtree|move)\b",
        re.IGNORECASE,
    ),
    "network": re.compile(
        r"\brequests\.(?:get|post|put|delete|patch)\s*\("
        r"|\burllib\.request\b"
        r"|\bhttp\.client\b"
        r"|\bfetch\s*\("
        r"|\baxios\.\w+\s*\("
        r"|\bnet\.connect\b|\bsocket\.\w+\s*\(",
        re.IGNORECASE,
    ),
    "sql": re.compile(
        r"\bcursor\.execute\s*\("
        r"|\.execute\s*\([^)]*(?:select|insert|update|delete)\b"
        r"|\bsqlite3\.connect\s*\(",
        re.IGNORECASE,
    ),
}

MAX_BLOCK_LINES = 40  # cap on how far a "tool block" extends past its definition
SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}


@register
class ToolAnnotationRisk(Rule):
    id = "MCP013"
    name = "Tool risk annotation missing or contradicted"
    severity = Severity.MEDIUM
    owasp = "MCP03:2025"  # Tool Poisoning — misrepresenting what a tool actually does

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source"):
            if f.ext not in SOURCE_EXTS:
                continue
            lines = f.lines
            def_idxs = [i for i, line in enumerate(lines) if TOOL_DEF.search(line)]
            for pos, idx in enumerate(def_idxs):
                end = def_idxs[pos + 1] if pos + 1 < len(def_idxs) else len(lines)
                end = min(end, idx + MAX_BLOCK_LINES)
                block = "\n".join(lines[idx:end])

                caps = [name for name, pattern in CAPABILITIES.items() if pattern.search(block)]
                if not caps:
                    continue
                cap_label = "/".join(caps)

                if SAFE_CLAIM.search(block):
                    out.append(self.finding(
                        f, idx + 1, lines[idx],
                        title=f"Tool annotation contradicts detected {cap_label} capability",
                        detail="This tool's annotations claim readOnlyHint: true or "
                               "destructiveHint: false, but its implementation calls a "
                               f"{cap_label} sink. Annotations are informational only — the MCP "
                               "spec itself warns a server can claim readOnlyHint: true and still "
                               "write files. An agent (or reviewer) trusting this annotation will "
                               "under-scrutinize a genuinely risky call.",
                        severity=Severity.HIGH,
                    ))
                elif not ANNOTATION_KEY.search(block):
                    out.append(self.finding(
                        f, idx + 1, lines[idx],
                        title=f"Tool with {cap_label} capability has no risk annotations",
                        detail=f"This tool calls a {cap_label} sink but declares none of "
                               "readOnlyHint / destructiveHint / idempotentHint / openWorldHint. "
                               "Neither an agent deciding how much to trust this call nor a human "
                               "skimming the tool list has a structured signal that this tool can "
                               "act, not just read.",
                        severity=Severity.MEDIUM,
                    ))
        return out
