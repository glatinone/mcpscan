# Security Policy

## Reporting a vulnerability

If you find a security issue in `mcpscan` itself, please report it privately via
[GitHub Security Advisories](https://github.com/glatinone/mcpscan/security/advisories/new)
rather than opening a public issue. We aim to acknowledge reports within 72 hours.

## Scope & threat model

`mcpscan` is a **static, read-only** analyzer:

- It only **reads** files under the scanned path — it never executes scanned code,
  resolves dependencies, or makes network calls.
- It is a **heuristic** tool. It surfaces risk signals; it does not prove malice and
  will not catch every issue. Treat findings as a prompt for human review.
- Findings may include **false positives** (and false negatives). Use
  `# mcpscan: ignore[RULE]` or `.mcpscanignore` to tune, and please report
  systematic false positives as bugs.

## Handling of secrets

When the secrets rule (MCP005) matches, the matched token is **redacted** in all
output formats so reports can be shared safely. The original file is never modified.
