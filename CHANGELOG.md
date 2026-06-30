# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-06-30

### Added
- `mcpscan-mcp`: a zero-dependency MCP server exposing a read-only `scan` tool.
- Rule **MCP007** — path traversal in file-reading tools.
- Rule **MCP008** — SSRF in outbound-fetch tools.
- Rule **MCP009** — insecure deserialization (pickle / marshal / yaml.load / node-serialize).
- Suppression support: `.mcpscanignore` glob file and inline `# mcpscan: ignore[...]`.
- `--list-rules` to enumerate the active rule set.
- Dogfood: mcpscan scans its own source clean in CI.
- CLI exit-code tests and an MCP-server test suite.

## [0.1.0] - 2026-06-30

### Added
- Initial release: static supply-chain scanner for MCP servers and Claude Code projects.
- Rules **MCP001–MCP006**: command injection, tool poisoning + hidden Unicode,
  dangerous Claude Code hooks, over-broad permissions, leaked secrets, vulnerable SDKs.
- Output formats: colored text, JSON, and SARIF 2.1.0.
- Severity-based exit codes for CI gating.
- Vulnerable and clean test fixtures.

[Unreleased]: https://github.com/glatinone/mcpscan/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/glatinone/mcpscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/glatinone/mcpscan/releases/tag/v0.1.0
