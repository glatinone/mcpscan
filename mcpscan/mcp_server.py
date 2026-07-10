"""A tiny, zero-dependency MCP server exposing mcpscan as a callable tool.

Speaks JSON-RPC 2.0 over stdio (newline-delimited messages), implementing just
enough of the Model Context Protocol for a client to discover and call the
``scan`` tool. Run it with::

    mcpscan-mcp           # or: python -m mcpscan.mcp_server

and point an MCP client (e.g. Claude Desktop / Claude Code) at that command.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from . import __version__
from .discover import render_discovery_json, run_discovery
from .findings import Severity
from .report import render_json
from .scanner import scan

PROTOCOL_VERSION = "2024-11-05"

SCAN_TOOL = {
    "name": "scan",
    "description": (
        "Statically scan a local path (an MCP server, package, or .claude/ directory) "
        "for supply-chain security issues: tool poisoning, command injection, dangerous "
        "hooks, over-broad permissions, leaked secrets, vulnerable SDKs, path traversal "
        "and SSRF. Returns a JSON report. Read-only; never executes the scanned code."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File or directory to scan."},
            "min_severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Only include findings at or above this severity.",
                "default": "info",
            },
        },
        "required": ["path"],
    },
}

DISCOVER_TOOL = {
    "name": "discover",
    "description": (
        "Enumerate well-known MCP client config locations on this machine (Claude "
        "Desktop, Claude Code CLI, Cursor, VS Code, Windsurf) and scan whichever "
        "exist with mcpscan's normal rule set. Closes OWASP MCP09:2025 (Shadow MCP "
        "Servers) — surfaces servers a directory scan of a single project would "
        "never see, since these configs live outside any project tree. Returns a "
        "JSON report. Read-only; never executes the scanned code."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "min_severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Only include findings at or above this severity.",
                "default": "info",
            },
        },
    },
}


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _run_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    path = args.get("path")
    if not path:
        raise ValueError("'path' is required")
    threshold = Severity.parse(args.get("min_severity", "info"))
    report = scan(path)
    # Filter to the requested floor, but keep the full JSON shape.
    report.findings = report.at_or_above(threshold)
    return {
        "content": [{"type": "text", "text": render_json(report)}],
        "isError": False,
    }


def _run_discover(args: Dict[str, Any]) -> Dict[str, Any]:
    threshold = Severity.parse(args.get("min_severity", "info"))
    discovery = run_discovery()
    # Filter each location's report in place, same pattern as _run_scan.
    for r in discovery.results:
        if r.report:
            r.report.findings = r.report.at_or_above(threshold)
    return {
        "content": [{"type": "text", "text": render_discovery_json(discovery)}],
        "isError": False,
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handle one JSON-RPC request; return a response, or None for notifications."""
    method = req.get("method")
    req_id = req.get("id")

    # Notifications (no id) get no response.
    if req_id is None and method and method.startswith("notifications/"):
        return None

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcpscan", "version": __version__},
        })

    if method == "tools/list":
        return _result(req_id, {"tools": [SCAN_TOOL, DISCOVER_TOOL]})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        if name not in ("scan", "discover"):
            return _error(req_id, -32602, f"unknown tool: {name}")
        try:
            args = params.get("arguments") or {}
            result = _run_scan(args) if name == "scan" else _run_discover(args)
            return _result(req_id, result)
        except Exception as exc:  # surface as a tool error, not a transport error
            return _result(req_id, {
                "content": [{"type": "text", "text": f"{name} failed: {exc}"}],
                "isError": True,
            })

    if method == "ping":
        return _result(req_id, {})

    if req_id is not None:
        return _error(req_id, -32601, f"method not found: {method}")
    return None


def serve(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for raw in stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        resp = handle_request(req)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def main() -> int:  # pragma: no cover
    try:
        serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
