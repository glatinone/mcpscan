# 🛡️ mcpscan

**The supply-chain security scanner for MCP servers and Claude Code projects.**

Catch **tool-poisoning**, **command injection**, **risky permissions**, **dangerous hooks**,
**leaked secrets**, and **vulnerable SDK versions** — *before* you install someone else's
MCP server or clone their `.claude/` directory.

[![CI](https://github.com/glatinone/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/glatinone/mcpscan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)

---

## Why?

The MCP ecosystem exploded to 14,000+ servers in 2026 — and so did the attack surface:

- **30+ CVEs** filed against MCP servers in a single 60-day window, **~43% command injection**.
- A systemic **RCE** disclosed across MCP SDK implementations.
- **492 MCP servers** found exposed to the internet with zero auth.
- A new class of attack — **tool poisoning** — hides prompt-injection payloads inside the
  *descriptions* of MCP tools, invisible to the user but read verbatim by the agent.

You wouldn't `npm install` a random package without a second look. `mcpscan` is that second
look for the MCP supply chain.

## What makes it different

Most LLM security scanners (garak, agentic-radar, …) probe a *running* model. `mcpscan` is a
**static** scanner aimed squarely at the **MCP + Claude Code supply chain** — the manifests,
tool definitions, hooks, and permission files you're about to trust:

| Check | What it catches |
|-------|-----------------|
| 🧨 Command injection | `shell=True`, `os.system`, `child_process.exec` with interpolated input |
| ☠️ Tool poisoning | Prompt-injection phrases hidden in MCP tool descriptions / docstrings |
| 🪝 Dangerous hooks | `.claude/` hooks that pipe `curl ... | sh`, `eval`, or exfiltrate env |
| 🔓 Over-broad permissions | Wildcard `allow` rules, `Bash(*)`, auto-approve everything |
| 🔑 Leaked secrets | API keys / tokens committed into configs |
| 📦 Vulnerable SDK | Known-bad `@modelcontextprotocol/sdk` / `mcp` versions |

## Install

```bash
pipx install mcpscan        # recommended
# or
pip install mcpscan
```

## Usage

```bash
mcpscan ./some-mcp-server          # scan a folder
mcpscan ./repo --format sarif -o results.sarif   # for GitHub code scanning
mcpscan ./repo --min-severity high # only fail on high/critical
mcpscan ./repo --json              # machine-readable output
```

Exit code is non-zero when findings at or above `--min-severity` are present — drop it straight
into CI:

```yaml
- run: pipx run mcpscan . --min-severity high
```

## License

MIT
