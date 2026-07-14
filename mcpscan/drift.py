"""MCP014 — a remote MCP server's URL domain silently changed since the last
``--discover`` run.

This is a different angle on the same OWASP MCP09:2025 (Shadow MCP Servers)
territory ``--discover`` (v0.7.0) already covers: that feature answers "what's
configured right now"; this answers "did a *previously seen* server config get
silently rewritten between runs." That's exactly the mechanism Mitiga Labs
disclosed (2026-04-10): a malicious npm postinstall hook rewrites a known
server's URL in ``~/.claude.json`` to an attacker-controlled proxy, intercepting
OAuth bearer tokens (GitHub/Jira/Confluence) in transit. The server's *name* in
the config never changes, so a scan that only ever looks at the current state
can't tell "trusted server" from "trusted name, hijacked endpoint." Anthropic
classified the report out of scope, citing "requires initial code execution" as
a prerequisite — the silent config rewrite is exactly what happens *after* that
initial foothold, and it's the part a periodic scan can still catch.

Design, deliberately:

- Diff against a local baseline cache, not a hardcoded vendor-domain allowlist.
  A maintained list of "known-good" domains per server name would go stale
  immediately and either miss real vendors or false-positive on legitimate
  self-hosted deployments. A fingerprint of "what did *this* install look like
  the last time mcpscan ran here" needs no such list and still catches the
  actual attack pattern: an unauthorized, silent change to what the user
  already configured.
- First sighting of a server name at a location is never a finding — there's
  nothing to diff against yet. It's recorded as the new baseline, same as
  ``--discover`` itself records "checked, not present" rather than guessing.
- A domain change *is* a finding, and the new domain becomes the baseline going
  forward — "alert once, then trust the new state," not a permanent lock. A
  legitimate migration (a team moving a self-hosted server to a new domain)
  trips this exactly once; a silent hijack also trips it exactly once, which
  is the point of a tripwire — one automated pass catches either.
- Local, stdio/command-launched servers have no domain and are out of scope —
  the same boundary MCP012 (auth gaps) already draws for the same reason.
- Only the hostname is fingerprinted (scheme/port/path/query ignored) — a
  server adding a query param or switching a path isn't a trust-boundary
  change; a changed hostname is who you're actually talking to.

Discovery-only, and deliberately not a normal :class:`~.rules.base.Rule`: a
`Rule` is a stateless function of the files in front of it, but this check
needs state that persists *across* runs (the baseline cache) and only makes
sense for the known, named server entries ``--discover`` already enumerates —
running it against an arbitrary project's `mcp.json` would either need the
same cross-run state (which a one-off project scan has no business keeping)
or silently do nothing. It still carries a `Rule`-shaped id/name/severity/owasp
so it can appear in `--list-rules` and flow through the existing SARIF/JSON/
text renderers exactly like every other finding.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional
from urllib.parse import urlsplit

from .discover import DiscoveryResult, _home
from .findings import Finding, Severity
from .rules.auth_gaps import _URL_KEYS, _iter_server_entries
from .rules.base import Rule

RULE_ID = "MCP014"


class DomainDriftRule(Rule):
    """Descriptor only — see module docstring for why this isn't registered."""

    id = RULE_ID
    name = "Remote MCP server domain changed since last --discover scan (discovery-only)"
    severity = Severity.HIGH
    owasp = "MCP04:2025"  # Software Supply Chain Attacks & Dependency Tampering


# Not decorated with @register: this never runs via the normal per-file scan
# (`mcpscan/scanner.py`'s `rules_pkg.all_rules()` loop) — only `check_drift()`,
# called explicitly from `--discover`, produces its findings.
DRIFT_RULE = DomainDriftRule()


def default_baseline_path() -> str:
    """Where the domain baseline lives, overridable for tests/CI isolation."""
    override = os.environ.get("MCPSCAN_BASELINE_PATH")
    if override:
        return override
    return os.path.join(_home(), ".mcpscan", "discover_baseline.json")


def _load_baseline(path: str) -> Dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    servers = data.get("servers")
    return dict(servers) if isinstance(servers, dict) else {}


def _save_baseline(path: str, servers: Dict[str, str]) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "servers": servers}, fh, indent=2, sort_keys=True)


def _domain(url: str) -> Optional[str]:
    host = urlsplit(url).hostname
    return host.lower() if host else None


def _baseline_key(location_path: str, server_name: str) -> str:
    return f"{location_path}::{server_name}"


def check_drift(discovery: DiscoveryResult, baseline_path: Optional[str] = None) -> None:
    """Diff every present location's remote server domains against the local
    baseline, in place: appends a Finding to that location's report for every
    domain change, then persists the updated baseline.

    Call this once per real ``--discover`` invocation, right after
    :func:`~.discover.run_discovery`. A missing/unreadable/unwritable baseline
    file degrades gracefully to "nothing to diff against yet," never to an
    error — a first run anywhere, or a read-only filesystem, just means the
    tripwire doesn't arm until a baseline can actually be written.
    """
    path = baseline_path or default_baseline_path()
    baseline = _load_baseline(path)
    changed = False

    for result in discovery.results:
        if not result.found or result.report is None:
            continue
        try:
            with open(result.location.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue

        for name, cfg in _iter_server_entries(data):
            url = next((cfg.get(k) for k in _URL_KEYS if isinstance(cfg.get(k), str)), None)
            if not url or not url.startswith(("http://", "https://")):
                continue  # local/stdio server: no domain to fingerprint
            domain = _domain(url)
            if not domain:
                continue

            key = _baseline_key(result.location.path, name)
            previous = baseline.get(key)
            if previous is not None and previous != domain:
                result.report.add(Finding(
                    rule_id=RULE_ID,
                    title=f"'{name}' now points at a different domain than last scan",
                    severity=DRIFT_RULE.severity,
                    path=os.path.basename(result.location.path),
                    line=0,
                    detail=(
                        f"Previously seen at '{previous}', now '{domain}'. If this server's "
                        "URL wasn't intentionally changed, treat this as a possible silent "
                        "config hijack (e.g. a malicious install script rewriting this file) "
                        "rather than routine drift — verify before trusting it again."
                    ),
                    snippet=f'"{name}": {{"url": "{url}"}}',
                    owasp=DRIFT_RULE.owasp,
                ))
            if previous != domain:
                baseline[key] = domain
                changed = True

    if changed:
        try:
            _save_baseline(path, baseline)
        except OSError:
            pass
