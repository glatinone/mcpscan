# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.1] - 2026-07-06

### Fixed
- **MCP006 drift audit**: `KNOWN_BAD`'s patched-version baselines were stale relative to
  disclosed CVEs and had gone unaudited since v0.1.0. Raised all three:
  - `@modelcontextprotocol/sdk`: `1.12.0` -> `1.26.0` (CVE-2026-25536 cross-client data
    leak via shared transport/server reuse; also folds in the 1.25.2 ReDoS fix,
    CVE-2026-0621).
  - `mcp`: `1.9.0` -> `1.23.0` (CVE-2025-66416, no DNS-rebinding protection by default on
    localhost HTTP servers; also folds in the 1.9.4 malformed-request DoS fix,
    CVE-2025-53366).
  - `fastmcp`: `2.3.0` -> `3.2.0` (GHSA-vv7q-7jx5-f767, critical unescaped-path-param
    traversal/SSRF in `OpenAPIProvider`; also folds in the CVE-2026-27124 OAuth
    confused-deputy fix and the GHSA-m8x7-r2rg-vh5g Windows install command-injection
    fix, both patched in the same release line).

  Any project pinning a version between an old and new baseline (e.g.
  `fastmcp==2.14.7`, the latest release on the old 2.x line) was a false negative
  before this release. Added dedicated `MCP006` unit tests so future drift shows up as
  a failing assertion instead of silent staleness.

## [0.4.0] - 2026-07-03

### Added
- `--fix`: preview one-line mechanical fixes for fixable findings as a unified diff plus a
  one-line explanation of why the original pattern is dangerous (dry run, no writes).
- `--apply-fix`: write those fixes to disk.
- `--list-rules` now shows a `FIX` column so you know which rules `--fix` covers.
- Mechanical fixes for **MCP009** (`yaml.load(x)` -> `yaml.safe_load(x)`, single-argument
  calls only — anything with an explicit `Loader=` is left for a human) and **MCP010**
  (`verify=False` / `check_hostname=False` dropped, `ssl.CERT_NONE` -> `ssl.CERT_REQUIRED`,
  `ssl._create_unverified_context()` -> `ssl.create_default_context()`,
  `rejectUnauthorized: false` -> `true`, `NODE_TLS_REJECT_UNAUTHORIZED=0` -> `=1`).
- Rules opt into fixability via a new `Rule.fix_line()` hook (default: not fixable).
  Deliberately unfixed: `shell=True` (needs the command turned into an argv list, not a
  value swap) and `pickle.loads` (needs a replacement format chosen by a human).

### Fixed
- `mcpscan/__init__.py`'s `__version__` was still `0.3.0` after the 0.3.1 release
  (only `pyproject.toml` had been bumped). Both now read `0.4.0`.

## [0.3.1] - 2026-07-03

### Added
- Rule **MCP012** — remote MCP servers with no authentication or a hardcoded static token.
  Flags `mcpServers` / `servers` entries pointing at an `http(s)://` URL that have no
  Authorization / API-key header at all (High), or one that's a literal token instead of an
  environment reference like `${TOKEN}` (Medium). Local, command/stdio-launched servers are
  out of scope. Motivated by 2026 field data showing 60-90% of real MCP deployments run with
  no auth or a long-lived static token — a far bigger real-world exposure than tool-poisoning
  alone.

## [0.3.0] - 2026-07-03

### Added
- Rule **MCP010** — disabled TLS verification (`verify=False`, `rejectUnauthorized: false`).
- Rule **MCP011** — over-broad `WebFetch` domain allowances: `WebFetch(domain:*)`, a bare
  TLD wildcard (`*.com`), or a `WebFetch` allow-entry with no domain filter at all.
- Reusable composite **GitHub Action** (`uses: glatinone/mcpscan@v0.2.0`).

### Fixed
- MCP004's "inside a `deny` block" detection only protected the first line or two after
  the `"deny"` key, so a wildcard denied on the second-or-later line of a multi-line
  `deny` array could still fire as a false positive. Replaced with bracket-depth tracking
  (`deny_block_lines`, shared by MCP004 and the new MCP011) that covers the whole array.

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

[Unreleased]: https://github.com/glatinone/mcpscan/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/glatinone/mcpscan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/glatinone/mcpscan/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/glatinone/mcpscan/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/glatinone/mcpscan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/glatinone/mcpscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/glatinone/mcpscan/releases/tag/v0.1.0
