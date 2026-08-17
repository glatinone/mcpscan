"""Tool description/schema drift detection ("rug pull") across live calls.

`mcpscan.drift` (MCP014) already fingerprints something adjacent — a remote MCP
server's *domain* — across `--discover` runs, catching a config file silently
rewritten to point at an attacker's proxy. This module fingerprints a different
signal: a *tool's own* description and input schema, on any transport (including
local stdio servers, which have no domain for MCP014 to track at all), checked on
every call rather than only via `--discover`.

Same rationale as `mcpscan.drift.DomainDriftRule` for why this isn't a normal
`mcpscan.rules.base.Rule`: a `Rule` is a stateless function of the files in front
of it, but this needs state that persists *across calls within a live session* —
there's nothing to diff against on a one-off static scan of a single file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolFingerprint:
    """SHA-256 fingerprint of a tool's description and schema."""

    description_hash: str
    schema_hash: str


@dataclass(frozen=True)
class DriftReport:
    """Describes a detected change for a previously-seen tool."""

    server: str
    tool_name: str
    description_changed: bool
    schema_changed: bool

    @property
    def changed(self) -> bool:
        return self.description_changed or self.schema_changed

    def __str__(self) -> str:
        what = []
        if self.description_changed:
            what.append("description")
        if self.schema_changed:
            what.append("input schema")
        return (
            f"rug-pull suspected: tool {self.tool_name!r} on server {self.server!r} "
            f"changed its {' and '.join(what)} since it was last loaded"
        )


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fingerprint(description: str, schema_repr: str) -> ToolFingerprint:
    """Compute the fingerprint for a given description and schema representation.

    *schema_repr* should be a stable string representation of the tool's input
    schema (e.g. ``json.dumps(schema, sort_keys=True)``); the caller controls how
    a schema is serialized so this module stays dependency-free.
    """
    return ToolFingerprint(
        description_hash=_hash(description), schema_hash=_hash(schema_repr)
    )


class RugPullLedger:
    """Per-process record of the last-seen fingerprint for each (server, tool) pair.

    Not persisted across process restarts, unlike MCP014's on-disk baseline —
    a deployment that needs drift detection across restarts should back this
    with a durable store (file, Redis, etc.) using the same fingerprinting.
    """

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], ToolFingerprint] = {}

    def check(
        self, server: str, tool_name: str, description: str, schema_repr: str = ""
    ) -> DriftReport | None:
        """Record the current fingerprint; return a DriftReport if it changed.

        Returns None the first time a (server, tool_name) pair is seen, and
        None on every subsequent call where nothing changed.
        """
        key = (server, tool_name)
        current = fingerprint(description, schema_repr)
        prior = self._seen.get(key)
        self._seen[key] = current

        if prior is None:
            return None

        description_changed = prior.description_hash != current.description_hash
        schema_changed = prior.schema_hash != current.schema_hash
        if not description_changed and not schema_changed:
            return None

        return DriftReport(
            server=server,
            tool_name=tool_name,
            description_changed=description_changed,
            schema_changed=schema_changed,
        )

    def known_tools(self) -> tuple[tuple[str, str], ...]:
        """Return the (server, tool_name) pairs currently tracked."""
        return tuple(self._seen.keys())
