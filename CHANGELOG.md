# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.13.0] - 2026-07-17

### Added
- **MCP018 — debug/proxy/inspector server bound to all interfaces exposes an
  unauthenticated connect/exec endpoint.** Motivated by
  `research/2026-07-17.md`'s top compounding opportunity: this exact
  vulnerability shape has now been independently confirmed twice in the MCP
  tooling ecosystem itself, not in some adjacent space — Anthropic's own MCP
  Inspector (CVE-2025-49596, CVSS 9.4) and MCPJam Inspector (CVE-2026-23744,
  CVSS 9.8, no user interaction required), roughly eight months apart. Both
  bound their HTTP proxy to every network interface instead of localhost and
  accepted a raw command/args payload on a connect-style endpoint with no
  authentication, achieving remote code execution from a single crafted
  request.

  New `mcpscan/rules/debug_endpoint.py`, a line-window heuristic (no AST, no
  YAML/JSON parse) requiring two co-occurring conditions in the same source
  file: (1) a bind call exposing every network interface — an explicit
  all-interfaces host (`0.0.0.0`, `::`, or an empty host string), or a Node
  `.listen(port)` call with no host argument (which defaults to all
  interfaces); (2) a route/handler whose path looks like a debug/inspector
  connect-or-exec endpoint, which spawns a process using a command/args value
  read directly out of the request body, with no authentication check
  anywhere in the handler. Critical severity, `MCP07:2025` (Insufficient
  Authentication & Authorization — same category as MCP010/MCP012, since the
  finding is the absence of a credential check, not the process-spawn
  mechanism itself). Deliberately conservative, matching the rest of
  mcpscan's "high signal over recall" design: only fires on the literal shape
  both disclosed CVEs share, not on every HTTP server that happens to spawn a
  process anywhere in the file.

  Found and fixed a self-scan regression while building this, the same class
  already documented for MCP013/MCP015: the new unit tests in
  `tests/test_debug_endpoint.py` construct a literal Node.js-shaped fixture
  string to exercise the rule directly, and that literal string looks exactly
  like a real vulnerable handler to the new rule once the whole repo gets
  self-scanned. Fixed with a single `# mcpscan: ignore[MCP018]` comment on
  the one affected line, the same suppression pattern already established
  for this exact class of problem.

  9 new tests (`tests/test_debug_endpoint.py`): the vulnerable shape firing
  in both Python/Flask and Node/Express styles, a localhost-only bind staying
  clean, an authentication check in the handler staying clean, an unrelated
  route path staying clean, a hardcoded-argv spawn staying clean, bind-all
  with no connect route staying clean, a connect route with no bind-all
  anywhere staying clean, and an out-of-scope file extension staying clean.
  New vulnerable/clean `server.py` fixture additions demonstrate the
  vulnerable and fixed pattern side by side. 109 tests passing (was 100).
  Dogfood self-scan clean — verified end-to-end with the real CLI against
  both fixture directories before committing, not just unit tests.

## [0.12.0] - 2026-07-16

### Added
- **MCP017 — untrusted-trigger workflow reaches a custom secret with no
  environment or identity gate.** The identity-based-trust half of the
  CI-workflow rule category deliberately deferred from v0.11.0. Motivated by
  `research/2026-07-16.md`'s top compounding opportunity: "Cordyceps," a
  2026-07 disclosure that scanned roughly 30,000 high-impact repositories and
  confirmed 300+ exploitable on this exact shape (workflows granting an
  untrusted PR/issue trigger more reach than it needs, with no special access
  required to exploit it) — the same root cause as the 2026-07-07 "GitLost"
  disclosure and MCP015/MCP016, now independently confirmed at scale across
  real organizations (Microsoft, Google, Apache, Cloudflare, the Python
  Software Foundation).

  Scoped narrower than the full "model every bot's own trust config" version
  the v0.11.0 TODO originally described (which needs per-Action schema
  knowledge a generic scanner can't verify without guessing): checks the
  generic, action-agnostic shape Cordyceps actually confirmed — a workflow
  triggered by untrusted content (`pull_request_target`, `issue_comment`,
  `issues`, `discussion`, `discussion_comment`) that references a *custom*
  secret (`${{ secrets.SOMETHING }}`) with neither of the two
  GitHub-documented gates present anywhere in the file: a protected
  `environment:` (requires manual reviewer approval before the job's secrets
  become available) or an explicit actor/`author_association` check.
  Deliberately excludes `${{ secrets.GITHUB_TOKEN }}` — that token's scope is
  already governed by the `permissions:` block, a distinct mechanism MCP016
  already reasons about; custom secrets aren't scoped by `permissions:` at
  all, which is exactly why the environment/actor gates matter here. High
  severity, `MCP02:2025` (Privilege Escalation via Scope Creep — the same
  category as MCP004/MCP011, since the root cause is a workflow granting more
  reach than it needs, not a code-execution primitive).

  Same line-window heuristic style as MCP015/MCP016, in the same
  `mcpscan/rules/workflow_injection.py` file. Found and fixed a real bug while
  building this: the first draft's `environment:` and actor-gate regexes used
  `^` against a `"\n".join(lines)` string without `re.MULTILINE`, so the
  anchor only matched the very start of the file — every gate was silently
  ignored regardless of where it appeared, which meant the finding fired even
  on workflows that correctly declared an `environment:` gate. Caught by the
  new unit tests before this shipped, not after.

  9 new tests (`tests/test_workflow_injection.py`): issue_comment and
  pull_request_target triggers with a custom secret and no gate both firing,
  list-form `on:` triggers, `GITHUB_TOKEN`-only staying clean, an
  `environment:` gate suppressing the finding, an `author_association` gate
  suppressing it, a `github.actor` allowlist gate suppressing it, a trusted
  (`pull_request`) trigger staying clean, and no-secret-reference staying
  clean. New vulnerable fixture
  (`tests/fixtures/vulnerable/.github/workflows/secrets_reach.yml`) and clean
  fixture (`tests/fixtures/clean/.github/workflows/comment-bot.yml`, gated
  behind a real `environment:` key) demonstrating both the vulnerable and the
  fixed pattern side by side. Found and fixed a second bug while building the
  clean fixture: its original wording ("Notify an external webhook") tripped
  the unrelated MCP003 hooks rule, since that rule's scope check is
  `"hook" in f.text.lower()` and "webhook" contains "hook" as a substring —
  reworded to "Notify a deployment service" instead of narrowing MCP003's
  scope check, since MCP003's broad text-based scope is itself intentional
  (a hook-like command can appear anywhere, not just `.claude/` config).
  100 tests passing (was 91). Dogfood self-scan clean. Verified end-to-end
  with the real CLI against both fixture directories and this repo's own
  `.github/workflows/*.yml` (neither `ci.yml` nor `release.yml` trigger on an
  untrusted event, so neither is affected) before committing.

## [0.11.0] - 2026-07-15

### Added
- **New rule category: CI workflow scanning (`.github/workflows/*.yml`).** The
  first mcpscan rules to look at a file type other than an MCP server's own
  source or config. Motivated by `research/2026-07-14.md` Pain Radar #1 and
  `research/2026-07-15.md`'s top compounding opportunity: a public GitHub
  issue can hijack agentic CI workflows across multiple vendors (Flatt
  Security's Claude Code Action disclosure, the 2026-07-07 "GitLost"
  disclosure, Microsoft's Copilot confirmation), all sharing the same root
  cause — untrusted issue/PR/comment content gets treated as instructions or
  code instead of data. Two textbook, well-documented GitHub Actions
  vulnerability classes now have dedicated checks:

  - **MCP015 — script injection.** An attacker-controlled context expression
    (an issue title, PR body, review comment, branch name) interpolated
    directly as `${{ ... }}` inside a `run:`/`script:` step instead of being
    passed through an `env:` variable first. See [GitHub's hardening
    guide](https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections).
    High severity, `MCP05:2025` (Command Injection & Execution).
  - **MCP016 — "pwn request."** A workflow triggers on `pull_request_target`
    (base-repo secrets and write-scoped token, even for a fork PR) and checks
    out the fork's own head commit via `actions/checkout` — the fork's code
    now executes with the base repo's trust level. See [GitHub Security
    Lab's "Preventing pwn
    requests"](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/).
    Critical severity, `MCP04:2025` (Supply Chain & Dependency Tampering).

  Both are line-window heuristics over the raw YAML text, not a full YAML
  parse, keeping mcpscan zero-dependency — the same regex-based style every
  other rule already uses. Both are deliberately conservative: a workflow that
  already follows the safe pattern (env-var indirection for MCP015; the
  `pull_request` trigger or a reviewer-gated environment for MCP016) never
  matches, since the specific unsafe shape being checked for simply isn't
  present in safe code.

  New `tests/test_workflow_injection.py` (12 tests): direct interpolation in
  both block and single-line `run:` steps, `env:` indirection staying clean,
  `github-script`'s `script:` block as an equivalent sink, trusted contexts
  (`matrix.*`) staying clean, non-workflow YAML files out of scope, step
  boundaries correctly ending a block/lookahead scan, `pull_request_target` in
  both mapping and list trigger forms, `pull_request` (without `_target`)
  staying clean, and a fork-checkout-free `pull_request_target` job staying
  clean. New vulnerable/clean workflow YAML fixtures
  (`tests/fixtures/vulnerable/.github/workflows/triage.yml`,
  `tests/fixtures/clean/.github/workflows/ci.yml`). 91 tests passing (was 79).
  Dogfood self-scan clean — this repo's own `ci.yml`/`release.yml` use neither
  unsafe pattern. Verified end-to-end with the real CLI against both fixture
  directories, not just unit tests.

## [0.10.0] - 2026-07-14

### Added
- **Rule MCP014 — remote MCP server domain changed since the last `--discover`
  run.** Closes a gap named in `research/2026-07-14.md`: Mitiga Labs (2026-04-10)
  disclosed a malicious npm postinstall hook silently rewriting a trusted server's
  URL in `~/.claude.json` to an attacker-controlled proxy, intercepting OAuth
  bearer tokens in transit — while the server's *name* in the config never
  changes, so a one-time scan can't tell "trusted server" from "trusted name,
  hijacked endpoint." Anthropic classified the report out of scope, citing
  "requires initial code execution" as a prerequisite; the silent config rewrite
  is exactly what happens *after* that foothold, and it's the part a periodic
  scan can still catch.

  Every `--discover` run now diffs each remote server's URL hostname against a
  local baseline (`~/.mcpscan/discover_baseline.json`, overridable via
  `MCPSCAN_BASELINE_PATH`) — a fingerprint cache, not a maintained vendor-domain
  allowlist, since the latter would go stale immediately and either miss real
  vendors or false-positive on self-hosted deployments. First sighting of a
  server name records the baseline with no finding; a domain change raises
  **MCP014** (high severity, `MCP04:2025` — Supply Chain / Dependency Tampering)
  and the new domain becomes the baseline going forward, so this alerts once per
  change rather than permanently locking a server to its first-ever domain — a
  legitimate migration and a real hijack both trip it exactly once, which is the
  point of a tripwire. Local, stdio-launched servers have no domain and stay out
  of scope, the same boundary MCP012 already draws.

  Deliberately not a normal per-file `Rule`: this check needs state that
  persists *across* runs, which a stateless rule contract doesn't model. New
  `mcpscan/drift.py` holds the baseline read/write/diff logic and a
  `DomainDriftRule` descriptor (id/name/severity/owasp only, not registered in
  the normal rule registry) so `MCP014` still shows up in `--list-rules` and
  flows through the existing SARIF/JSON/text renderers unchanged.

  Verified end-to-end against a real subprocess invocation of the CLI (not just
  unit tests): a two-run scenario reproducing the disclosed attack pattern
  exactly (server name `"github"` unchanged, URL rewritten to an
  attacker-controlled domain) correctly flips the second run's exit code from
  `0` to `1` with the MCP014 finding printed. 11 new tests
  (`tests/test_drift.py`: first-sighting baseline write, domain-change finding,
  alert-once-then-trust-new-state, unchanged-domain no-op, stdio-server
  out-of-scope, corrupt-baseline graceful degradation, env-var override,
  `--list-rules` inclusion, and a CLI-level two-invocation exit-code test); 79
  tests passing (was 68). Dogfood self-scan clean.

## [0.9.0] - 2026-07-14

### Added
- **Rule MCP013 — tool risk annotation missing or contradicted.** Built on the MCP
  spec's own structured `ToolAnnotations` schema (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`) instead of parsing freeform description prose —
  a stable, standardized field is more precise and easier to test than
  keyword-matching risk language. Two checks:
  1. **Absence** — a tool detected calling a high-risk capability (subprocess/exec,
     filesystem write/delete, outbound network, SQL) ships with none of the four
     annotation keys at all.
  2. **Contradiction** — a tool claims `readOnlyHint: true` or `destructiveHint:
     false` while its own implementation calls one of those same capability sinks.
     A stronger finding than absence: not "risk unstated" but "risk actively
     misrepresented."

  The MCP project's own docs are explicit that annotations are informational, not
  enforced ("an untrusted server can claim `readOnlyHint: true` and delete your
  files anyway") — check 2 is exactly that gap made concrete. Tool boundaries are a
  line-window heuristic (a Python `@x.tool(...)` decorator, a raw `Tool(name=...)`
  construction, or a JS/TS `registerTool(...)` / `.tool("name", ...)` call, up to the
  next tool definition or a 40-line cap), not AST-derived — mcpscan stays
  zero-dependency and regex-based, so this trades recall on unusual registration
  patterns for zero new false-positive surface. Maps to
  [MCP03:2025](#-owasp-mcp-top-10-mapping) (Tool Poisoning): both checks are about a
  tool's own metadata misrepresenting what it does, the same category MCP002
  already covers for hidden-instruction descriptions.

  7 new tests (`TestToolAnnotationsRule`); 68 tests passing (was 61). Dogfood
  self-scan clean.

## [0.8.0] - 2026-07-10

### Added
- **`--discover` now supports `--format sarif`**: one SARIF 2.1.0 run spanning every
  discovered location, so `mcpscan --discover -f sarif -o discover.sarif` uploads to
  GitHub code scanning the same way a normal scan does. Results point at each
  client's full config path (`location.path`), not the bare filename a single-file
  scan records — Cursor's and VS Code's configs are both named `mcp.json`, and the
  bare filename alone wouldn't tell a SARIF viewer which one a result came from.
  `mcpscan/report.py`'s SARIF rule/result builders (`_sarif_rules`, `_sarif_result`)
  were factored out of `render_sarif()` so this reuses the same shape instead of
  duplicating it.
- **`discover` tool on `mcpscan-mcp`**: the MCP server now exposes two tools,
  `scan(path, min_severity?)` and `discover(min_severity?)`, so an agent can ask
  "what's actually configured on this machine" the same way it already asks `scan`.
  Closes the second of the two `--discover` follow-ups noted in v0.7.0.

Both follow-ups close out the `--discover` roadmap item from v0.7.0, except
fleet-wide aggregation across machines, which needs an inventory/agent backend this
project doesn't have and stays a documented future roadmap item, not a gap.

5 new tests (3 for discovery-mode SARIF, 2 for the `discover` MCP tool); 61 tests
passing (was 56). Dogfood self-scan clean.

## [0.7.0] - 2026-07-09

### Added
- **`--discover` mode**: closes the OWASP MCP09:2025 ("Shadow MCP Servers") coverage
  gap. Checks well-known, user-scope MCP client config paths — Claude Desktop, Claude
  Code CLI (`~/.claude.json`), Cursor (`~/.cursor/mcp.json`), VS Code/Copilot user
  profile, Windsurf — and runs the normal rule set against whichever ones actually
  exist on this machine. Per-machine only by design (no fleet/remote-collection step);
  a location that doesn't exist is reported as "checked, not present," not silently
  skipped, so a clean report can't be misread as "nothing installed." Supports
  `--format text`/`json`; `sarif` and `--fix`/`--apply-fix` aren't wired up for
  discovery yet. New `mcpscan/discover.py`; path expansion resolves HOME/APPDATA via
  env vars first (not OS-native `expanduser`/`expandvars`) so every platform's path
  table is unit-testable from one CI runner. Verified against a real machine before
  shipping: `--discover` on this machine's own `~/.claude.json` surfaced two real
  MCP004 (wildcard permission) findings that a normal `mcpscan .` scan would never
  have seen, since that file lives outside any project directory. New
  `tests/test_discover.py` (10 tests); 56 tests passing (was 46). Dogfood self-scan
  clean.

## [0.6.0] - 2026-07-08

### Added
- **OWASP MCP Top 10 mapping**: every finding now carries an `owasp` field
  (e.g. `MCP05:2025`) tagging it against the official
  [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) taxonomy (v0.1, Phase 3
  beta/pilot). The mapping was taken directly from the project's
  [source file](https://github.com/OWASP/www-project-mcp-top-10/blob/main/tab_top10.md),
  not a secondary summary, after an earlier check found two summaries disagreeing on
  MCP06's title. Surfaced in `--list-rules` (new OWASP column), the `text`/`json` report
  formats, and as an `owaspMcpTop10` property on both the rule descriptor and each
  result in `sarif` output. New `mcpscan/owasp.py` holds the canonical id-to-title table;
  a new test asserts every rule maps to a real category. 4 of the 10 OWASP categories
  (MCP06, MCP08, MCP09, MCP10) aren't covered by any current rule — documented as gaps,
  not silently ignored, in the README's mapping table. 46 tests passing (was 41).
  Dogfood self-scan clean.

## [0.5.0] - 2026-07-07

### Added
- `.pre-commit-hooks.yaml`: mcpscan can now be installed as a
  [pre-commit](https://pre-commit.com) hook.
  ```yaml
  repos:
    - repo: https://github.com/glatinone/mcpscan
      rev: v0.5.0
      hooks:
        - id: mcpscan
  ```
  The hook always scans the whole working tree (`pass_filenames: false`) rather than
  only the files in the commit, since permission/config rules like MCP004 and MCP012
  need the full picture, not one file in isolation. Defaults to `--min-severity=high`,
  overridable via `args:` in the consumer's config. See README's new
  "As a pre-commit hook" section.

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

[Unreleased]: https://github.com/glatinone/mcpscan/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/glatinone/mcpscan/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/glatinone/mcpscan/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/glatinone/mcpscan/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/glatinone/mcpscan/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/glatinone/mcpscan/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/glatinone/mcpscan/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/glatinone/mcpscan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/glatinone/mcpscan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/glatinone/mcpscan/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/glatinone/mcpscan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/glatinone/mcpscan/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/glatinone/mcpscan/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/glatinone/mcpscan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/glatinone/mcpscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/glatinone/mcpscan/releases/tag/v0.1.0
