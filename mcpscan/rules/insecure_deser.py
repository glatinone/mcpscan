"""MCP009 — insecure deserialization.

Deserializing attacker-influenced data with pickle / marshal / yaml.load is a
direct path to remote code execution. A tool that accepts serialized blobs and
loads them is especially dangerous in an MCP server, where the input often comes
from an untrusted caller.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# Always-dangerous Python sinks.
PICKLE = re.compile(r"\b(?:pickle|cPickle|_pickle)\.(?:load|loads)\s*\(")
MARSHAL = re.compile(r"\bmarshal\.(?:load|loads)\s*\(")
# yaml.load without an explicit safe loader.
YAML_LOAD = re.compile(r"\byaml\.load\s*\(")
YAML_SAFE = re.compile(r"Safe(?:C)?Loader|safe_load")
# A single-argument yaml.load(x) call — safe to mechanically rewrite. Anything
# with a second argument (e.g. an explicit Loader=) needs a human to check it.
YAML_LOAD_SIMPLE = re.compile(r"\byaml\.load\(([^,()]*)\)")
# Node insecure deserialization.
JS_UNSERIALIZE = re.compile(r"\b(?:node-serialize|serialize)\s*\.\s*unserialize\s*\(|\bunserialize\s*\(")


@register
class InsecureDeserialization(Rule):
    id = "MCP009"
    name = "Insecure deserialization"
    severity = Severity.HIGH

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source"):
            is_py = f.ext == ".py"
            for i, line in enumerate(f.lines, start=1):
                s = line.strip()
                if s.startswith("#") or s.startswith("//"):
                    continue

                hit = sev = None
                if is_py and PICKLE.search(line):
                    hit = "pickle deserialization"
                    sev = Severity.CRITICAL
                elif is_py and MARSHAL.search(line):
                    hit = "marshal deserialization"
                    sev = Severity.HIGH
                elif is_py and YAML_LOAD.search(line) and not YAML_SAFE.search(line):
                    hit = "yaml.load without SafeLoader"
                    sev = Severity.HIGH
                elif not is_py and JS_UNSERIALIZE.search(line):
                    hit = "node-serialize unserialize()"
                    sev = Severity.CRITICAL

                if hit:
                    out.append(self.finding(
                        f, i, line,
                        title=f"Insecure deserialization: {hit}",
                        detail="Never deserialize untrusted input with these APIs. Use a safe "
                               "format (JSON) or a safe loader (yaml.safe_load) and validate "
                               "the schema.",
                        severity=sev,
                    ))
        return out

    def fix_line(self, line: str) -> Optional[Tuple[str, str]]:
        if YAML_SAFE.search(line):
            return None
        m = YAML_LOAD_SIMPLE.search(line)
        if not m:
            return None
        fixed = YAML_LOAD_SIMPLE.sub(r"yaml.safe_load(\1)", line, count=1)
        return fixed, ("yaml.safe_load() only builds basic Python types (dict, list, str, "
                        "int...), so it can't be tricked into instantiating arbitrary "
                        "objects the way yaml.load() can.")
