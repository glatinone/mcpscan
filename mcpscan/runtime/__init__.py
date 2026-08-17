"""Runtime guards: live defenses applied while an agent is actually talking to
an MCP server, complementing the static, pre-install scanning in `mcpscan.rules`.

- `mcpscan.runtime.sanitizer.MCPDescriptionSanitizer` — screens tool metadata live,
  reusing MCP002's detection engine (`mcpscan.rules.tool_poisoning`) as the single
  source of truth so static and runtime judgments never diverge.
- `mcpscan.runtime.provenance.ProvenanceWrapper` — caps and boundary-tags live tool
  output before it re-enters an agent's context. Nothing in the static scanner does
  this, since it never executes a tool.
- `mcpscan.runtime.rugpull.RugPullLedger` — fingerprints a tool's own description/schema
  across repeated calls to the same server, catching a swapped tool ("rug pull").
  Complementary to MCP014 (`mcpscan.drift`), which only fingerprints *remote server
  domains* across `--discover` runs; this covers a different signal (a tool's own
  metadata, on any transport, checked on every call) that MCP014 does not.
- `mcpscan.runtime.guard.MCPToolGuard` — composite facade over all three.

None of these are registered as a `mcpscan.rules.base.Rule`: a `Rule` is a stateless
function of the files in front of it, but these need state that persists across live
calls (the ledger) or content that only exists at call time (tool output) — the same
reasoning `mcpscan.drift.DomainDriftRule` already documents for why it isn't a normal
registered rule either.
"""
