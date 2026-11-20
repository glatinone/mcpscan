"""MCP007 — path traversal in file-reading tools.

A tool that opens a path built from its arguments lets a caller walk out of the
intended directory (``../../etc/passwd``) and read arbitrary files. We flag file
reads whose path is interpolated/concatenated rather than a constant literal.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

# File-open sinks. `window.open(` is browser JS embedded in a Python string, not a file open.
PY_OPEN = re.compile(
    r"(?<!window\.)\bopen\s*\(|\.read_text\s*\(|\.read_bytes\s*\(|send_file\s*\(|FileResponse\s*\(",
)
JS_OPEN = re.compile(
    r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(|\breadFile(?:Sync)?\s*\(",
)
# Path is dynamically built (concat / f-string / template / join with a var).
INTERP = re.compile(r"`[^`]*\$\{|\+\s*\w|f['\"]|\.format\(|os\.path\.join\([^)]*\b\w")
# Explicit traversal token sitting in a literal.
TRAVERSAL = re.compile(r"\.\./|\.\.\\")
# A function that does either of these is treated as confining its paths to a base dir.
BOUNDARY_CALL = re.compile(r"\w*(?:safe_path|validate_path)\w*\s*\(")
RESOLVE = re.compile(r"\b(?:realpath|resolve)\s*\(")
PREFIX_CHECK = re.compile(r"\b(?:startswith|is_relative_to|commonpath)\s*\(")
# Parameters that never carry caller input (pytest fixtures included).
NOT_CALLER_INPUT = {"self", "cls", "tmp_path", "tmpdir"}
TWO_PATH_SINKS = {("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
                  ("shutil", "move"), ("os", "rename"), ("os", "replace")}


def _derived(value: ast.AST, tainted: set) -> bool:
    """`p`, `p[k]`, `p.get(k)`, `base / p`, or Path/abspath/str/os.path.join over p, where p is tainted."""
    if isinstance(value, ast.Name):
        return value.id in tainted
    if isinstance(value, ast.Subscript):
        return _derived(value.value, tainted)
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
        return _derived(value.left, tainted) or _derived(value.right, tainted)
    if isinstance(value, ast.Call):
        fn = value.func
        if isinstance(fn, ast.Attribute) and fn.attr == "get":
            return _derived(fn.value, tainted)
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        return name in ("Path", "abspath", "str", "join") \
            and any(_derived(a, tainted) for a in value.args)
    return False


def _is_join(value: ast.AST) -> bool:
    """`os.path.join(...)` or `base / name`: a path built onto a base directory."""
    if isinstance(value, ast.BinOp):
        return isinstance(value.op, ast.Div)
    return isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) \
        and value.func.attr == "join" and isinstance(value.func.value, ast.Attribute) \
        and value.func.value.attr == "path"


def _write_targets(call: ast.Call) -> List[ast.AST]:
    """Path arguments of a filesystem write sink, or [] if `call` is not one."""
    fn = call.func
    if isinstance(fn, ast.Name) and fn.id == "open" and call.args:
        mode = call.args[1] if len(call.args) > 1 else next(
            (k.value for k in call.keywords if k.arg == "mode"), None)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) \
                and set(mode.value) & set("wax+"):
            return [call.args[0]]
        return []
    if not isinstance(fn, ast.Attribute):
        return []
    if fn.attr in ("write_text", "write_bytes"):
        return [fn.value]
    if isinstance(fn.value, ast.Name) and (fn.value.id, fn.attr) in TWO_PATH_SINKS:
        return list(call.args[:2])
    return []


def _save_targets(call: ast.Call) -> List[ast.AST]:
    """openpyxl/PIL-style `wb.save(path)`. One positional arg skips torch/np.save(obj, path).
    Only a path joined in the same function counts: a helper handed a finished path
    (`wb.save(filepath)`) is checked where that path is built."""
    fn = call.func
    if isinstance(fn, ast.Attribute) and fn.attr == "save" and len(call.args) == 1:
        return [call.args[0]]
    return []


def _param_write_lines(text: str) -> List[Tuple[int, bool]]:
    """(line, is_builder) where a function writes to, or returns a path joined from, one of its
    own parameters (or `arguments.get(...)`/`arguments[...]` of one) with no base-dir check."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    hits = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = ast.get_source_segment(text, fn) or ""
        if BOUNDARY_CALL.search(src) or (RESOLVE.search(src) and PREFIX_CHECK.search(src)):
            continue
        a = fn.args
        tainted = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs} - NOT_CALLER_INPUT
        joined = set()  # tainted names built with os.path.join or `/`
        steps = sorted((n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.For))),
                       key=lambda n: n.lineno)
        for n in steps:
            if isinstance(n, ast.For):  # `for item in tainted_list` taints item
                target, value = n.target, n.iter
            else:
                target, value = (n.targets[0] if len(n.targets) == 1 else None), n.value
            if isinstance(target, ast.Name) and _derived(value, tainted):
                tainted.add(target.id)
                if _is_join(value) or _derived(value, joined):
                    joined.add(target.id)
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and (
                    any(_derived(t, tainted) for t in _write_targets(n))
                    or any(_derived(t, joined) or (_is_join(t) and _derived(t, tainted))
                           for t in _save_targets(n))):
                hits[n.lineno] = False
            elif isinstance(n, ast.Return) and n.value is not None and _is_join(n.value) \
                    and _derived(n.value, tainted):
                hits.setdefault(n.lineno, True)
    return sorted(hits.items())


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
            if is_py:
                seen = {x.line for x in out if x.path == f.relpath}
                for i, builder in _param_write_lines(f.text):
                    if i in seen:
                        continue
                    if builder:
                        out.append(self.finding(
                            f, i, f.lines[i - 1],
                            title="Path helper joins a caller-controlled name onto a base "
                                  "directory with no containment check",
                            detail="os.path.join/`/` keep an absolute name and `../` walks out of "
                                   "the base. Resolve the result and confirm it stays inside the "
                                   "base (realpath + commonpath, or resolve() + is_relative_to) "
                                   "before returning it (CVE-2026-40576 shape).",
                            severity=Severity.MEDIUM,
                        ))
                        continue
                    out.append(self.finding(
                        f, i, f.lines[i - 1],
                        title="Write to a caller-controlled path with no base-directory check",
                        detail="The written path is a function parameter. Resolve it and confirm it "
                               "stays inside an allowed base directory (Path.resolve() + "
                               "is_relative_to) before writing (CVE-2026-27825 shape).",
                        severity=Severity.HIGH,
                    ))
        return out
