"""Live counterpart to MCP002 (tool poisoning).

`mcpscan.rules.tool_poisoning` catches injected instructions and hidden Unicode
in tool descriptions *statically*, when a project is scanned before install. But
a description can also be fetched live — over stdio/SSE, after `--discover` or a
static scan already passed, or from a server that wasn't scanned at all (dynamic
tool discovery, a server added at runtime). This module screens description text
at that moment too, right before it would be bound to an agent's prompt.

Deliberately reuses `INJECTION` and `HIDDEN_UNICODE` from `mcpscan.rules.tool_poisoning`
rather than defining a second, parallel pattern set: a tool description judged safe by
a static scan and then judged differently by a live check (or vice versa) would be a
worse outcome than either check alone — one detection engine, two call sites.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..rules.tool_poisoning import HIDDEN_UNICODE, INJECTION

DEFAULT_MAX_LENGTH = 500
REDACTION_MARKER = "[REMOVED]"
HIDDEN_UNICODE_MARKER = "␣"  # same visible stand-in MCP002 itself uses ("␣")


@dataclass(frozen=True)
class SanitizationResult:
    """Outcome of screening one piece of live tool metadata."""

    text: str
    """The screened text: injection phrases redacted, hidden Unicode made visible,
    length-capped."""

    flagged: bool
    """True if anything was redacted, replaced, or truncated."""

    injection_found: bool = False
    """True if MCP002's INJECTION pattern matched."""

    hidden_unicode_found: bool = False
    """True if MCP002's HIDDEN_UNICODE pattern matched."""

    truncated: bool = False
    """True if the text exceeded max_length and was cut."""


class MCPDescriptionSanitizer:
    """Screens MCP-supplied text for tool poisoning at call time.

    One instance per policy (length cap + markers); it holds no per-call
    state, so it's safe to share across threads/tasks.
    """

    def __init__(
        self,
        *,
        max_length: int = DEFAULT_MAX_LENGTH,
        redaction_marker: str = REDACTION_MARKER,
        hidden_unicode_marker: str = HIDDEN_UNICODE_MARKER,
    ) -> None:
        self._max_length = max_length
        self._redaction_marker = redaction_marker
        self._hidden_unicode_marker = hidden_unicode_marker

    def sanitize(self, text: str) -> SanitizationResult:
        """Redact injection phrasing and hidden Unicode in *text*, then cap its length."""
        working, hidden_count = HIDDEN_UNICODE.subn(self._hidden_unicode_marker, text)
        working, injection_count = INJECTION.subn(self._redaction_marker, working)

        truncated = len(working) > self._max_length
        if truncated:
            working = working[: self._max_length] + "... [truncated]"

        return SanitizationResult(
            text=working,
            flagged=bool(hidden_count) or bool(injection_count) or truncated,
            injection_found=bool(injection_count),
            hidden_unicode_found=bool(hidden_count),
            truncated=truncated,
        )
