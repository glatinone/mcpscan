"""``--discover``: enumerate known MCP client config locations on this machine.

Closes OWASP MCP09:2025 (Shadow MCP Servers). A normal `mcpscan <path>` scan
only ever sees what you point it at; most engineers don't remember every MCP
client they've installed, so a laptop routinely has MCP server configs a
security review never sees. This module answers a narrower, cheaper question
than full shadow-IT discovery: on *this* machine, which of the well-known MCP
client config files exist, and what does mcpscan's existing rule set find in
each one.

Scope, deliberately:

- Per-machine only. There is no fleet/remote-collection piece here — that
  needs an inventory or agent backend this project doesn't have. Run this on
  each machine you want visibility into.
- Only *known, standard* config paths are checked (Claude Desktop, Claude
  Code CLI, Cursor, VS Code, Windsurf — see ``known_locations()`` for exact
  paths and sources). This is not a filesystem-wide crawl for anything named
  "mcp.json" outside a project; that's already what a normal directory scan
  does for a project you're already reviewing.
- A location that doesn't exist on this OS/user account is not a finding —
  it's recorded as "checked, not present" so a report can't be misread as
  "everything is clean" when a client was simply never installed here.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from .findings import Finding, Report
from .scanner import scan_files


def _home() -> str:
    """Home directory, resolved via env vars first so this stays testable.

    ``os.path.expanduser("~")`` is correct at runtime but its behavior is
    tied to the *actual* host OS, not a value we can override in a test —
    checking HOME/USERPROFILE ourselves first means the known-location table
    can be exercised for every OS branch from a single CI runner.
    """
    return os.environ.get("HOME") or os.environ.get("USERPROFILE") or os.path.expanduser("~")


def _appdata() -> str:
    return os.environ.get("APPDATA") or os.path.join(_home(), "AppData", "Roaming")


@dataclass(frozen=True)
class ClientLocation:
    client: str   # human label, e.g. "Claude Desktop"
    path: str     # absolute path this OS/account would use


def known_locations(platform: Optional[str] = None) -> List[ClientLocation]:
    """Well-known, user-scope MCP client config paths for *platform*.

    Defaults to :data:`sys.platform`; a caller (tests) can pass another
    value to inspect what mcpscan would check on a different OS.

    Deliberately excludes project-scoped files (``.cursor/mcp.json``,
    ``.vscode/mcp.json``, a repo's own ``.mcp.json``) — those already surface
    in a normal directory scan of the project. This table is only the
    global/user-level configs a directory scan would never see because
    they live outside any project tree.

    Sources (verified, not guessed, 2026-07-09):
    - Claude Desktop: Anthropic's own MCP quickstart / support docs.
    - Cursor: cursor.com/docs/mcp.
    - VS Code / Copilot: code.visualstudio.com/docs/agents/reference/mcp-configuration.
    - Claude Code CLI: code.claude.com/docs/en/mcp.
    - Windsurf: docs.windsurf.com/windsurf/cascade/mcp.
    """
    plat = platform or sys.platform
    home = _home()
    appdata = _appdata()
    out: List[ClientLocation] = []

    if plat == "win32":
        out.append(ClientLocation("Claude Desktop", os.path.join(appdata, "Claude", "claude_desktop_config.json")))
    elif plat == "darwin":
        out.append(ClientLocation("Claude Desktop", os.path.join(
            home, "Library", "Application Support", "Claude", "claude_desktop_config.json")))
    else:
        out.append(ClientLocation("Claude Desktop", os.path.join(
            home, ".config", "claude-desktop", "claude_desktop_config.json")))

    # Claude Code CLI — global, user-scope servers live under ~/.claude.json.
    # Project-scope (.mcp.json) and local-scope (also inside ~/.claude.json,
    # but keyed per-project) are out of scope here for the same reason as
    # Cursor/VS Code project files above.
    out.append(ClientLocation("Claude Code CLI (user)", os.path.join(home, ".claude.json")))

    out.append(ClientLocation("Cursor (global)", os.path.join(home, ".cursor", "mcp.json")))

    if plat == "win32":
        out.append(ClientLocation("VS Code (user)", os.path.join(appdata, "Code", "User", "mcp.json")))
    elif plat == "darwin":
        out.append(ClientLocation("VS Code (user)", os.path.join(
            home, "Library", "Application Support", "Code", "User", "mcp.json")))
    else:
        out.append(ClientLocation("VS Code (user)", os.path.join(home, ".config", "Code", "User", "mcp.json")))

    out.append(ClientLocation("Windsurf", os.path.join(home, ".codeium", "windsurf", "mcp_config.json")))

    return out


@dataclass
class LocationResult:
    location: ClientLocation
    found: bool
    report: Optional[Report] = None


@dataclass
class DiscoveryResult:
    results: List[LocationResult] = field(default_factory=list)
    platform: str = ""

    @property
    def found_count(self) -> int:
        return sum(1 for r in self.results if r.found)

    def all_findings(self) -> List[Finding]:
        return [f for r in self.results if r.report for f in r.report.findings]


def run_discovery(platform: Optional[str] = None) -> DiscoveryResult:
    """Check every known location; scan the ones that exist with the normal rule set."""
    plat = platform or sys.platform
    result = DiscoveryResult(platform=plat)
    for loc in known_locations(plat):
        if not os.path.isfile(loc.path):
            result.results.append(LocationResult(loc, found=False))
            continue
        report, _files = scan_files(loc.path)
        report.root = loc.path
        result.results.append(LocationResult(loc, found=True, report=report))
    return result


def render_discovery_text(discovery: DiscoveryResult, color: bool = True) -> str:
    from .report import render_text  # local import: avoid a report<->discover cycle

    lines = [f"mcpscan --discover  checked {len(discovery.results)} known MCP client "
              f"config location(s) for {discovery.platform}", ""]
    for r in discovery.results:
        loc = r.location
        if not r.found:
            lines.append(f"[ ] {loc.client} — not present ({loc.path})")
            continue
        lines.append(f"[x] {loc.client} — {loc.path}")
        lines.append(render_text(r.report, color=color))
    findings = discovery.all_findings()
    lines.append(f"Discovery summary: {discovery.found_count}/{len(discovery.results)} "
                 f"location(s) present, {len(findings)} finding(s) total.")
    return "\n".join(lines)


def render_discovery_sarif(discovery: DiscoveryResult) -> str:
    """SARIF 2.1.0 for a discovery run, one ``run`` spanning every location.

    Reuses :func:`report._sarif_rules`/``_sarif_result`` rather than
    duplicating SARIF's rule/result shape here. Results are pointed at each
    location's full config path (``location.path``), not ``finding.path`` —
    a single-file scan records only the bare filename (e.g. ``mcp.json``),
    which collides across clients (Cursor and VS Code both use that name) and
    wouldn't tell a reader which location a result came from.
    """
    from .report import _sarif_rules, _sarif_result  # local: avoid report<->discover cycle

    all_findings = discovery.all_findings()
    results = [
        _sarif_result(f, r.location.path)
        for r in discovery.results if r.found and r.report
        for f in r.report.sorted()
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpscan",
                "informationUri": "https://github.com/glatinone/mcpscan",
                "rules": _sarif_rules(all_findings),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def render_discovery_json(discovery: DiscoveryResult) -> str:
    payload = {
        "tool": "mcpscan",
        "mode": "discover",
        "platform": discovery.platform,
        "locations": [
            {
                "client": r.location.client,
                "path": r.location.path,
                "found": r.found,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.label,
                        "path": f.path,
                        "line": f.line,
                        "detail": f.detail,
                        "snippet": f.snippet,
                        "owasp": f.owasp,
                    }
                    for f in r.report.sorted()
                ] if r.found and r.report else [],
            }
            for r in discovery.results
        ],
        "found_count": discovery.found_count,
        "total_findings": len(discovery.all_findings()),
    }
    return json.dumps(payload, indent=2)
