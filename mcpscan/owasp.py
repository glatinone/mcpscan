"""OWASP MCP Top 10 (2025) reference taxonomy.

Source of truth: https://github.com/OWASP/www-project-mcp-top-10/blob/main/tab_top10.md
(the raw content backing https://owasp.org/www-project-mcp-top-10/), read directly
rather than from a summary, since a wrong category id in a security tool is worse
than no mapping at all. Version v0.1, Phase 3 (beta release / pilot testing) as of
2026-07-08 — categories and titles may still shift before a final release.

Used by `mcpscan/rules/*.py` (`Rule.owasp`) to tag findings with a category id, and
by tests to make sure every tagged rule points at a real category.
"""

from __future__ import annotations

# category id (e.g. "MCP01:2025") -> official title
OWASP_MCP_TOP_10 = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    "MCP06:2025": "Prompt Injection via Contextual Payloads",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}
