"""MCP024-MCP030 — server-side authorization mistakes in Python MCP servers.

Every other auth-adjacent rule in mcpscan (MCP012, MCP018, MCP022) looks at how
a client *connects to* a server or whether an endpoint is exposed at all. These
rules look at how a server *validates* the bearer tokens it receives, following
the MCP authorization spec (2025-06-18 onward, unchanged in 2026-07-28):

    MCP024  JWT decoded with signature verification disabled
    MCP025  JWT audience not validated (RFC 8707: servers MUST check `aud`)
    MCP026  JWT issuer not validated
    MCP027  hand-rolled 401 with no `WWW-Authenticate: Bearer resource_metadata=...`
    MCP028  hand-rolled bearer auth with no Protected Resource Metadata endpoint
    MCP029  token passthrough: the client's own token forwarded downstream
    MCP030  access token accepted from the URL query string

Built after an experiment in which mcpscan 0.20, Semgrep (200 rules) and Bandit
all reported *identical* findings for a deliberately naive MCP server that
failed 8 authorization tests and for its hardened twin. Everything here uses the
Python AST, not regex, so string literals, comments and docs never match.

Scope gating, for precision: the rules only look at Python files that look like
an MCP server (import `mcp`/`fastmcp`, or handle the JSON-RPC `tools/call` /
`tools/list` methods), plus — when the scan contains such a server — any other
Python file that reads an inbound `Authorization` header (a split-out auth
module). Generic web apps, OAuth clients and scripts that decode a JWT to peek
at its claims are left alone.

Bugs these rules deliberately do NOT try to catch, because the evidence only
exists at runtime: a missing per-tool scope check, and `tools/list` being
reachable anonymously. Test those against a running server.
"""

from __future__ import annotations

import ast
import functools
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

_JSONRPC_METHODS = {"tools/call", "tools/list"}
_MCP_MODULES = ("mcp", "fastmcp")
_PRM_PATH = "oauth-protected-resource"
_JWT_DECODE_ATTRS = {"decode", "decode_complete"}


# --------------------------------------------------------------------------
# Parsing + per-file facts (cached: seven rules share one parse per file)
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=512)
def _parse(text: str) -> Optional[ast.AST]:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _str_constants(tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def _is_str(node: Optional[ast.AST], *values: str) -> bool:
    return (isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value.lower() in values)


@functools.lru_cache(maxsize=512)
def _facts(text: str) -> Optional[dict]:
    tree = _parse(text)
    if tree is None:
        return None
    imports_mcp = False
    jwt_names: Set[str] = set()       # names bound to PyJWT / python-jose `jwt`
    jwt_decode_names: Set[str] = set()  # `from jwt import decode`
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _MCP_MODULES:
                    imports_mcp = True
                if a.name == "jwt":
                    jwt_names.add(a.asname or "jwt")
                elif a.name == "jose.jwt" and a.asname:
                    jwt_names.add(a.asname)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            root = node.module.split(".")[0]
            if root in _MCP_MODULES:
                imports_mcp = True
            for a in node.names:
                if node.module == "jose" and a.name == "jwt":
                    jwt_names.add(a.asname or "jwt")
                elif node.module in ("jwt", "jose.jwt") and a.name in _JWT_DECODE_ATTRS:
                    jwt_decode_names.add(a.asname or a.name)
    consts = set(_str_constants(tree))
    return {
        "tree": tree,
        "mcp": imports_mcp or bool(consts & _JSONRPC_METHODS),
        "jwt_names": jwt_names,
        "jwt_decode_names": jwt_decode_names,
        "reads_auth_header": any(_is_auth_header_read(n) for n in ast.walk(tree)),
        "consts_lower": " ".join(consts).lower(),
    }


def _is_auth_header_read(node: ast.AST) -> bool:
    """`<x>.headers.get("Authorization")`, `<x>.headers["Authorization"]`,
    `<x>.getheader("Authorization")`, `request.META["HTTP_AUTHORIZATION"]`."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
        attr = node.func.attr
        if attr == "get" and _is_headers_obj(node.func.value):
            return _is_str(node.args[0], "authorization")
        if attr in ("getheader", "get_header"):
            return _is_str(node.args[0], "authorization")
        if attr == "get" and _attr_name(node.func.value) == "META":
            return _is_str(node.args[0], "http_authorization")
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        key = node.slice
        if _is_headers_obj(node.value) and _is_str(key, "authorization"):
            return True
        if _attr_name(node.value) == "META" and _is_str(key, "http_authorization"):
            return True
    return False


def _attr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_headers_obj(node: ast.AST) -> bool:
    """`request.headers`, `handler.headers`, `self.headers`, `self.request.headers`.

    Deeper chains such as `response.request.headers` are the headers of a
    request this code *sent*, not of the one it received, so they don't count.
    """
    if not (isinstance(node, ast.Attribute) and node.attr == "headers"):
        return False
    owner = node.value
    if isinstance(owner, ast.Name):
        return True
    return (isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name)
            and owner.value.id in ("self", "cls"))


def _is_test_file(f: FileInfo) -> bool:
    parts = f.relpath.lower().split("/")
    name = parts[-1]
    return (any(p in ("test", "tests") for p in parts[:-1])
            or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py")


def _py_sources(files: List[FileInfo]) -> List[FileInfo]:
    # Test suites mint tokens, decode them to inspect claims and assert on 401s;
    # these rules are about how a *server* behaves, so tests are out of scope.
    return [f for f in by_kind(files, "source") if f.ext == ".py" and not _is_test_file(f)]


def _in_scope(files: List[FileInfo]) -> List[Tuple[FileInfo, dict]]:
    """Python files these rules apply to (see module docstring)."""
    facts = [(f, _facts(f.text)) for f in _py_sources(files)]
    facts = [(f, x) for f, x in facts if x is not None]
    any_server = any(x["mcp"] for _, x in facts)
    return [(f, x) for f, x in facts
            if x["mcp"] or (any_server and x["reads_auth_header"])]


def _project_mentions(files: List[FileInfo], needle: str) -> bool:
    """True if any scanned source file mentions *needle* as code, not comment.

    Python files are checked via their string constants; other source files
    fall back to raw text. Only ever used to *suppress* a finding, so the looser
    fallback can't add noise.
    """
    for f in by_kind(files, "source"):
        if _is_test_file(f):
            continue  # a test asserting on the header proves nothing about the server
        if f.ext == ".py":
            x = _facts(f.text)
            if x is not None and needle in x["consts_lower"]:
                return True
        elif needle in f.text.lower():
            return True
    return False


# SDK helpers that serve Protected Resource Metadata on the server's behalf.
_PRM_SDK_NAMES = {"create_protected_resource_routes", "ProtectedResourceMetadata",
                  "AuthSettings", "RemoteAuthProvider"}


@functools.lru_cache(maxsize=512)
def _serves_prm_py(text: str) -> bool:
    """True if this Python file routes the PRM well-known path or uses an SDK helper.

    A PRM URL that is only ever *built* (e.g. an f-string in a property nobody
    routes) doesn't count: the path has to appear in a comparison
    (`path == "/.well-known/..."`, `path in (...)`) or as a call argument
    (`@app.get("/.well-known/...")`, `Route(...)`, `path.startswith(...)`).
    """
    tree = _parse(text)
    if tree is None:
        return False

    def has_prm(nodes) -> bool:
        for n in nodes:
            if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
                if has_prm(n.elts):
                    return True
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) \
                    and _PRM_PATH in n.value.lower():
                return True
        return False

    for n in ast.walk(tree):
        if isinstance(n, ast.Compare) and has_prm([n.left] + list(n.comparators)):
            return True
        if isinstance(n, ast.Call) and has_prm(list(n.args) + [k.value for k in n.keywords]):
            return True
        if isinstance(n, ast.Dict) and has_prm([k for k in n.keys if k is not None]):
            return True  # {"/.well-known/...": handler} route tables
        if _attr_name(n) in _PRM_SDK_NAMES and isinstance(n, (ast.Name, ast.Attribute)):
            return True
        if isinstance(n, ast.ImportFrom) and any(a.name in _PRM_SDK_NAMES for a in n.names):
            return True
    return False


def _project_serves_prm(files: List[FileInfo]) -> bool:
    for f in by_kind(files, "source"):
        if _is_test_file(f):
            continue
        if f.ext == ".py":
            if _serves_prm_py(f.text):
                return True
        elif _PRM_PATH in f.text.lower():
            return True  # non-Python: raw text, can only suppress
    return False


def _line(f: FileInfo, lineno: int) -> str:
    return f.lines[lineno - 1] if 0 < lineno <= len(f.lines) else ""


# --------------------------------------------------------------------------
# JWT decode calls (MCP024-MCP026)
# --------------------------------------------------------------------------

class _Decode:
    def __init__(self, call: ast.Call):
        self.call = call
        self.kw = {k.arg: k.value for k in call.keywords if k.arg}
        self.has_star_kwargs = any(k.arg is None for k in call.keywords)
        self.options = self._options()

    def _options(self) -> Dict[str, ast.AST]:
        opts = self.kw.get("options")
        if opts is None and len(self.call.args) >= 4:
            opts = self.call.args[3]  # positional options in both PyJWT and jose
        out: Dict[str, ast.AST] = {}
        if isinstance(opts, ast.Dict):
            for k, v in zip(opts.keys, opts.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    out[k.value] = v
        return out

    def opt_false(self, name: str) -> bool:
        v = self.options.get(name)
        return isinstance(v, ast.Constant) and v.value is False

    def signature_disabled(self) -> Optional[str]:
        if self.opt_false("verify_signature"):
            return 'options={"verify_signature": False}'
        v = self.kw.get("verify")  # PyJWT 1.x
        if isinstance(v, ast.Constant) and v.value is False:
            return "verify=False"
        algs = self.kw.get("algorithms")
        if algs is None and len(self.call.args) >= 3:
            algs = self.call.args[2]
        elts = algs.elts if isinstance(algs, (ast.List, ast.Tuple, ast.Set)) else [algs]
        if any(_is_str(e, "none") for e in elts if e is not None):
            return 'algorithms includes "none"'
        return None

    def opaque(self) -> bool:
        # **kwargs or a long positional list: we can't tell what's passed.
        return self.has_star_kwargs or len(self.call.args) > 4


def _jwt_decodes(tree: ast.AST, facts: dict) -> Iterable[_Decode]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr in _JWT_DECODE_ATTRS
                and isinstance(fn.value, ast.Name) and fn.value.id in facts["jwt_names"]):
            pass
        elif isinstance(fn, ast.Name) and fn.id in facts["jwt_decode_names"]:
            pass
        else:
            continue
        if node.args and _mentions_session_cookie(node.args[0]):
            continue  # a UI session cookie, not a bearer access token
        yield _Decode(node)


def _mentions_session_cookie(e: ast.AST) -> bool:
    for n in ast.walk(e):
        name = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else ""
        if "cookie" in name.lower():
            return True
    return False


@register
class JwtSignatureDisabled(Rule):
    id = "MCP024"
    name = "MCP server decodes JWT access tokens with signature verification disabled"
    severity = Severity.HIGH
    owasp = "MCP07:2025"  # Insufficient Authentication & Authorization

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f, x in _in_scope(files):
            for d in _jwt_decodes(x["tree"], x):
                why = d.signature_disabled()
                if not why:
                    continue
                out.append(self.finding(
                    f, d.call.lineno, _line(f, d.call.lineno),
                    detail=(f"jwt.decode() is called with {why}, so any caller can mint "
                            "a token with whatever `sub`, `scope` and `aud` they like and "
                            "it will be accepted. Verify the signature against the "
                            "authorization server's JWKS and pin `algorithms=` to the "
                            "asymmetric algorithm it actually uses (e.g. [\"RS256\"])."),
                ))
        return out


@register
class JwtAudienceNotValidated(Rule):
    id = "MCP025"
    name = "MCP server accepts JWT access tokens without validating the audience"
    severity = Severity.HIGH
    owasp = "MCP07:2025"

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f, x in _in_scope(files):
            for d in _jwt_decodes(x["tree"], x):
                if d.signature_disabled() or d.opaque():
                    continue  # MCP024 already covers it / can't tell
                if d.opt_false("verify_aud"):
                    why = 'options={"verify_aud": False} turns the audience check off'
                elif "audience" not in d.kw:
                    why = "no audience= argument is passed"
                else:
                    continue
                out.append(self.finding(
                    f, d.call.lineno, _line(f, d.call.lineno),
                    detail=(f"jwt.decode() in an MCP server: {why}. A token the same "
                            "authorization server minted for a different API is then "
                            "accepted here (confused deputy). The MCP authorization spec "
                            "requires servers to validate that the token was issued for "
                            "them (RFC 8707). Pass audience=<this server's canonical "
                            "resource URI>."),
                ))
        return out


@register
class JwtIssuerNotValidated(Rule):
    id = "MCP026"
    name = "MCP server accepts JWT access tokens without validating the issuer"
    severity = Severity.MEDIUM
    owasp = "MCP07:2025"

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f, x in _in_scope(files):
            for d in _jwt_decodes(x["tree"], x):
                if d.signature_disabled() or d.opaque():
                    continue
                if d.opt_false("verify_iss"):
                    why = 'options={"verify_iss": False} turns the issuer check off'
                elif "issuer" not in d.kw:
                    why = "no issuer= argument is passed"
                else:
                    continue
                out.append(self.finding(
                    f, d.call.lineno, _line(f, d.call.lineno),
                    detail=(f"jwt.decode() in an MCP server: {why}. Any issuer whose key "
                            "this server happens to trust can mint tokens it accepts. "
                            "Pass issuer=<your authorization server's issuer URL> (the "
                            "one advertised in your Protected Resource Metadata)."),
                ))
        return out


# --------------------------------------------------------------------------
# 401 handling and discovery (MCP027, MCP028)
# --------------------------------------------------------------------------

def _unauthorized_sites(tree: ast.AST) -> List[int]:
    """Line numbers where this file itself produces an HTTP 401."""
    lines: List[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            vals = list(node.args) + [k.value for k in node.keywords]
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            vals = list(node.value.elts)
        else:
            continue
        for v in vals:
            if isinstance(v, ast.Constant) and v.value == 401 and not isinstance(v.value, bool):
                lines.append(v.lineno)
            elif isinstance(v, ast.Attribute) and v.attr in ("UNAUTHORIZED", "HTTP_401_UNAUTHORIZED"):
                lines.append(v.lineno)
    return sorted(set(lines))


def _handles_bearer(x: dict) -> bool:
    return x["reads_auth_header"] or bool(x["jwt_names"] or x["jwt_decode_names"])


@register
class UnauthorizedWithoutResourceMetadata(Rule):
    id = "MCP027"
    name = "MCP server returns 401 without a WWW-Authenticate resource_metadata challenge"
    severity = Severity.MEDIUM
    owasp = "MCP07:2025"

    def check(self, files: List[FileInfo]) -> List[Finding]:
        scoped = [(f, x) for f, x in _in_scope(files) if x["mcp"] and _handles_bearer(x)]
        if not scoped or _project_mentions(files, "resource_metadata="):
            return []
        has_prm = _project_serves_prm(files)
        out: List[Finding] = []
        for f, x in scoped:
            sites = _unauthorized_sites(x["tree"])
            if not sites:
                continue
            out.append(self.finding(
                f, sites[0], _line(f, sites[0]),
                severity=Severity.LOW if has_prm else None,
                detail=("This MCP server builds its own 401 responses but nothing in the "
                        "project ever emits `WWW-Authenticate: Bearer "
                        "resource_metadata=\"...\"`. Without that challenge an MCP client "
                        "has no pointer to your Protected Resource Metadata"
                        + (" and must fall back to probing the well-known URI" if has_prm
                           else " and, with no well-known endpoint either, no way to "
                                "discover the authorization server at all")
                        + ". Add the header to every 401 (RFC 9728 section 5.1)."),
            ))
        return out


@register
class NoProtectedResourceMetadata(Rule):
    id = "MCP028"
    name = "MCP server does bearer auth but serves no Protected Resource Metadata"
    severity = Severity.MEDIUM
    owasp = "MCP07:2025"

    def check(self, files: List[FileInfo]) -> List[Finding]:
        scoped = [(f, x) for f, x in _in_scope(files) if x["mcp"] and _handles_bearer(x)]
        if not scoped or _project_serves_prm(files):
            return []
        out: List[Finding] = []
        for f, x in scoped:
            sites = _unauthorized_sites(x["tree"])
            if not sites:
                continue
            out.append(self.finding(
                f, sites[0], _line(f, sites[0]),
                detail=("This MCP server rejects unauthenticated requests itself, but no "
                        "file in the project serves `/.well-known/oauth-protected-resource`. "
                        "The MCP authorization spec requires servers to publish OAuth 2.0 "
                        "Protected Resource Metadata (RFC 9728) naming their "
                        "authorization server(s); without it a spec-following client "
                        "cannot start the OAuth flow."),
            ))
        return out


# --------------------------------------------------------------------------
# Token passthrough (MCP029) — small intra-module taint analysis
# --------------------------------------------------------------------------

_SRC = "SRC"
_STR_METHODS_FROM_ARGS = {"format", "join"}
_HEADER_SETTERS = {"add_header", "putheader", "add_unredirected_header"}


class _FuncInfo:
    def __init__(self, node, in_class: bool):
        self.name = node.name
        self.body = node.body
        params = [a.arg for a in node.args.posonlyargs + node.args.args]
        is_static = any(_attr_name(d) == "staticmethod" for d in node.decorator_list)
        self.bound_params = params[1:] if in_class and not is_static and params else params
        self.all_params = params
        self.returns: Set[str] = set()       # labels a call to this function yields
        self.sink_params: Set[str] = set()   # params that reach an outbound Authorization

    @classmethod
    def module(cls, tree: ast.Module) -> "_FuncInfo":
        self = cls.__new__(cls)
        self.name, self.body = "<module>", tree.body
        self.bound_params, self.all_params = [], []
        self.returns, self.sink_params = set(), set()
        return self


def _collect_funcs(tree: ast.AST) -> Dict[str, _FuncInfo]:
    funcs: Dict[str, _FuncInfo] = {}

    def visit(node, in_class):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.setdefault(child.name, _FuncInfo(child, in_class))
                visit(child, False)
            elif isinstance(child, ast.ClassDef):
                visit(child, True)
            else:
                visit(child, in_class)
    visit(tree, False)
    return funcs


class _Taint:
    """Flow-insensitive taint over one function body.

    Labels: "SRC" (derived from the inbound Authorization header) and
    "P:<name>" (derived from parameter <name>). Propagates through
    assignments, string building (f-strings, +, .format, slicing, method calls
    on a tainted string) and calls to same-module functions via their summary.
    Deliberately does NOT propagate through arbitrary function arguments, so
    `jwt.decode(token)` or `lookup_service_token(user)` stay clean.
    """

    def __init__(self, fn: _FuncInfo, funcs: Dict[str, _FuncInfo]):
        self.fn, self.funcs = fn, funcs
        self.env: Dict[str, Set[str]] = {p: {"P:" + p} for p in fn.all_params}
        self.aliases: Dict[str, Set[str]] = {}

    def _body_nodes(self):
        # Walk the function body, not nested defs/classes (they're analysed separately).
        stack = list(self.fn.body)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            yield n
            stack.extend(ast.iter_child_nodes(n))

    def run(self) -> List[Tuple[int, str, str]]:
        """Return sink hits as (line, label, description)."""
        nodes = list(self._body_nodes())
        for _ in range(6):  # fixed point over assignments
            changed = False
            for n in nodes:
                changed |= self._assign(n)
            if not changed:
                break
        returns: Set[str] = set()
        hits: List[Tuple[int, str, str]] = []
        for n in nodes:
            if isinstance(n, ast.Return) and n.value is not None:
                returns |= self.labels(n.value)
            hits.extend(self._sinks(n))
        self.fn.returns = returns
        return hits

    def _bind(self, target: ast.AST, labels: Set[str]) -> bool:
        changed = False
        if isinstance(target, ast.Name):
            cur = self.env.setdefault(target.id, set())
            if not labels <= cur:
                cur |= labels
                changed = True
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                changed |= self._bind(t, labels)
        elif isinstance(target, ast.Starred):
            changed |= self._bind(target.value, labels)
        return changed

    def _assign(self, n: ast.AST) -> bool:
        if isinstance(n, ast.Assign):
            names = self._func_refs(n.value)
            if names and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                # auth = authenticate  /  auth = strict if x else lax;  ...; auth(request)
                cur = self.aliases.setdefault(n.targets[0].id, set())
                if names <= cur:
                    return False
                cur |= names
                return True
            labels = self.labels(n.value)
            return any([self._bind(t, labels) for t in n.targets]) if labels else False
        if isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
            labels = self.labels(n.value)
            return self._bind(n.target, labels) if labels else False
        if isinstance(n, ast.NamedExpr):
            labels = self.labels(n.value)
            return self._bind(n.target, labels) if labels else False
        return False

    def _func_refs(self, e: ast.AST) -> Set[str]:
        if isinstance(e, ast.Name) and e.id in self.funcs:
            return {e.id}
        if isinstance(e, ast.IfExp):
            body, other = self._func_refs(e.body), self._func_refs(e.orelse)
            return body | other if body and other else set()
        return set()

    def _callees(self, call: ast.Call) -> List[Tuple[_FuncInfo, bool]]:
        fn = call.func
        if isinstance(fn, ast.Name):
            names = self.aliases.get(fn.id) or {fn.id}
            return [(self.funcs[n], False) for n in sorted(names) if n in self.funcs]
        if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                and fn.value.id in ("self", "cls") and fn.attr in self.funcs):
            return [(self.funcs[fn.attr], True)]
        return []

    def _arg_labels(self, call: ast.Call, info: _FuncInfo, bound: bool) -> Dict[str, Set[str]]:
        params = info.bound_params if bound else info.all_params
        out: Dict[str, Set[str]] = {}
        for i, a in enumerate(call.args):
            if i < len(params) and not isinstance(a, ast.Starred):
                out[params[i]] = self.labels(a)
        for k in call.keywords:
            if k.arg:
                out[k.arg] = self.labels(k.value)
        return out

    def labels(self, e: Optional[ast.AST]) -> Set[str]:
        if e is None:
            return set()
        if _is_auth_header_read(e):
            return {_SRC}
        if isinstance(e, ast.Name):
            return set(self.env.get(e.id, ()))
        if isinstance(e, ast.JoinedStr):
            return set().union(*(self.labels(v) for v in e.values)) if e.values else set()
        if isinstance(e, ast.FormattedValue):
            return self.labels(e.value)
        if isinstance(e, ast.BinOp):
            return self.labels(e.left) | self.labels(e.right)
        if isinstance(e, ast.BoolOp):
            return set().union(*(self.labels(v) for v in e.values))
        if isinstance(e, ast.IfExp):
            return self.labels(e.body) | self.labels(e.orelse)
        if isinstance(e, (ast.Tuple, ast.List)):
            return set().union(*(self.labels(v) for v in e.elts)) if e.elts else set()
        if isinstance(e, ast.Subscript):
            return self.labels(e.value)
        if isinstance(e, ast.Starred):
            return self.labels(e.value)
        if isinstance(e, ast.Await):
            return self.labels(e.value)
        if isinstance(e, ast.Call):
            callees = self._callees(e)
            if callees:
                out = set()
                for info, bound in callees:
                    args = self._arg_labels(e, info, bound)
                    for lab in info.returns:
                        out |= args.get(lab[2:], set()) if lab.startswith("P:") else {lab}
                return out
            fn = e.func
            if isinstance(fn, ast.Name) and fn.id == "str" and e.args:
                return self.labels(e.args[0])
            if isinstance(fn, ast.Attribute):
                out = self.labels(fn.value)  # tainted.strip(), h.split()[1], ...
                if fn.attr in _STR_METHODS_FROM_ARGS:
                    for a in e.args:
                        out |= self.labels(a)
                return out
        return set()

    def _sinks(self, n: ast.AST) -> List[Tuple[int, str, str]]:
        hits: List[Tuple[int, str, str]] = []

        def hit(node, labels, desc):
            for lab in labels:
                hits.append((node.lineno, lab, desc))

        if isinstance(n, ast.Call):
            fn = n.func
            if (isinstance(fn, ast.Attribute) and fn.attr in _HEADER_SETTERS
                    and len(n.args) >= 2 and _is_str(n.args[0], "authorization")):
                hit(n, self.labels(n.args[1]), f".{fn.attr}(\"Authorization\", ...)")
            for info, bound in self._callees(n):
                for p, labs in self._arg_labels(n, info, bound).items():
                    if p in info.sink_params:
                        hit(n, labs, f"{info.name}() which sets it as an outbound Authorization header")
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if _is_str(k, "authorization"):
                    hit(v, self.labels(v), '{"Authorization": ...} headers')
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and _is_str(t.slice, "authorization"):
                    hit(n, self.labels(n.value), 'headers["Authorization"] = ...')
        return hits


def _passthrough_hits(tree: ast.AST) -> List[Tuple[int, str]]:
    funcs = _collect_funcs(tree)
    module = _FuncInfo.module(tree)
    analysed = list(funcs.values()) + [module]
    hits: Dict[int, str] = {}
    for _ in range(6):  # fixed point over function summaries
        before = [(frozenset(f.returns), frozenset(f.sink_params)) for f in analysed]
        hits = {}
        for fn in analysed:
            for line, lab, desc in _Taint(fn, funcs).run():
                if lab == _SRC:
                    hits.setdefault(line, desc)
                elif lab.startswith("P:"):
                    fn.sink_params.add(lab[2:])
        after = [(frozenset(f.returns), frozenset(f.sink_params)) for f in analysed]
        if after == before:
            break
    return sorted(hits.items())


@register
class TokenPassthrough(Rule):
    id = "MCP029"
    name = "MCP server forwards the client's access token to a downstream API (token passthrough)"
    severity = Severity.HIGH
    owasp = "MCP01:2025"  # Token Mismanagement & Secret Exposure

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f, x in _in_scope(files):
            if not x["reads_auth_header"]:
                continue
            for line, desc in _passthrough_hits(x["tree"]):
                out.append(self.finding(
                    f, line, _line(f, line),
                    detail=(f"The inbound Authorization header reaches {desc}. The MCP "
                            "authorization spec forbids token passthrough: the client's "
                            "token was issued for this MCP server, and forwarding it lets a "
                            "downstream API trust a token not meant for it while bypassing "
                            "this server's own controls and audit trail. Call downstream "
                            "APIs with the server's own credential, or exchange the token "
                            "(RFC 8693) for one whose audience is the downstream API."),
                ))
        return out


# --------------------------------------------------------------------------
# Token in the query string (MCP030)
# --------------------------------------------------------------------------

_QUERY_ATTRS = {"args", "query_params", "GET", "query", "query_arguments"}
_QS_PARSERS = {"parse_qs", "parse_qsl"}


def _is_qs_parse(e: ast.AST) -> bool:
    if isinstance(e, ast.Call):
        if _attr_name(e.func) in _QS_PARSERS:
            return True
        if _attr_name(e.func) == "dict" and e.args:  # dict(parse_qsl(...))
            return _is_qs_parse(e.args[0])
    return False


def _query_token_reads(tree: ast.AST) -> List[int]:
    qs_names: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and _is_qs_parse(n.value):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    qs_names.add(t.id)

    def is_query_obj(e: ast.AST) -> bool:
        if isinstance(e, ast.Attribute) and e.attr in _QUERY_ATTRS:
            return True
        if isinstance(e, ast.Name) and e.id in qs_names:
            return True
        return _is_qs_parse(e)

    lines: List[int] = []
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("get", "getlist", "get_argument", "getone")
                and n.args and _is_str(n.args[0], "access_token")
                and (is_query_obj(n.func.value) or n.func.attr == "get_argument")):
            lines.append(n.lineno)
        elif isinstance(n, ast.Subscript):
            if _is_str(n.slice, "access_token") and is_query_obj(n.value) \
                    and isinstance(n.ctx, ast.Load):
                lines.append(n.lineno)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # FastAPI: def endpoint(access_token: str = Query(...))
            a = n.args
            pos = a.posonlyargs + a.args
            pairs = list(zip(pos[len(pos) - len(a.defaults):], a.defaults))
            pairs += [(k, d) for k, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]
            for arg, default in pairs:
                if (arg.arg == "access_token" and isinstance(default, ast.Call)
                        and _attr_name(default.func) == "Query"):
                    lines.append(arg.lineno)
    return sorted(set(lines))


@register
class AccessTokenFromQueryString(Rule):
    id = "MCP030"
    name = "MCP server accepts an access token from the URL query string"
    severity = Severity.MEDIUM
    owasp = "MCP01:2025"  # Token Mismanagement & Secret Exposure

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f, x in _in_scope(files):
            for line in _query_token_reads(x["tree"]):
                out.append(self.finding(
                    f, line, _line(f, line),
                    detail=("An `access_token` is read from the request's query string. "
                            "Tokens in URLs end up in proxy, server and browser logs and in "
                            "Referer headers; the MCP authorization spec says access tokens "
                            "MUST NOT be sent in the URI query string. Accept bearer tokens "
                            "only from the Authorization header, and reject requests that "
                            "carry ?access_token= outright."),
                ))
        return out
