"""Composite facade wiring the sanitizer, provenance wrapper, and rug-pull ledger.

This is the integration point: given a tool's raw metadata and (optionally) a
freshly-received output string, run all three defenses in one call. Each
component also works standalone for callers that only need one piece.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .provenance import ProvenanceResult, ProvenanceWrapper
from .rugpull import DriftReport, RugPullLedger
from .sanitizer import MCPDescriptionSanitizer, SanitizationResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolMetadataGuardResult:
    """Outcome of guarding a tool's metadata before it's bound to an agent."""

    safe_description: str
    sanitization: SanitizationResult
    drift: DriftReport | None


class MCPToolGuard:
    """Applies sanitization, rug-pull detection, and output tagging together."""

    def __init__(
        self,
        *,
        sanitizer: MCPDescriptionSanitizer | None = None,
        provenance: ProvenanceWrapper | None = None,
        ledger: RugPullLedger | None = None,
    ) -> None:
        self._sanitizer = sanitizer or MCPDescriptionSanitizer()
        self._provenance = provenance or ProvenanceWrapper()
        self._ledger = ledger or RugPullLedger()

    def guard_metadata(
        self,
        *,
        server: str,
        tool_name: str,
        description: str,
        schema_repr: str = "",
    ) -> ToolMetadataGuardResult:
        """Sanitize *description* (MCP002's engine) and check for drift.

        Call this once per tool, each time a tool list is loaded from a
        server, before binding the tool's description to an agent's prompt.
        """
        sanitization = self._sanitizer.sanitize(description)
        drift = self._ledger.check(server, tool_name, description, schema_repr)
        if drift is not None:
            logger.warning("%s", drift)
        return ToolMetadataGuardResult(
            safe_description=sanitization.text,
            sanitization=sanitization,
            drift=drift,
        )

    def guard_output(self, content: str, *, server: str, tool: str) -> ProvenanceResult:
        """Cap and provenance-tag a tool's output before it re-enters agent context."""
        return self._provenance.wrap(content, server=server, tool=tool)

    def system_prompt_addendum(self) -> str:
        """Instruction to append to the agent's system prompt for tagged content."""
        return self._provenance.system_prompt_addendum()
