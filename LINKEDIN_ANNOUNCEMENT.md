# LinkedIn Announcement — mcpscan on PyPI

mcpscan is now on PyPI.

pip install mcpscan

mcpscan is a static security scanner for MCP servers and Claude Code projects. It looks for the failure modes that show up once you let an LLM call tools: command injection in subprocess wrappers, prompt injection hidden in tool descriptions (tool poisoning), over-broad file or network permissions, hardcoded secrets in config, and unsafe deserialization.

Two design constraints shaped the tool:

Zero runtime dependencies. mcpscan is built entirely on the Python standard library. No third party packages to audit, no supply chain to inherit, and it runs in locked-down CI environments without a dependency install step. The scanner itself does static pattern analysis over source files, not full AST parsing, which keeps it dependency free and fast on large repos.

SARIF 2.1.0 output. Findings export in a format GitHub Code Scanning already understands, so results land in the Security tab like any other code scanning alert, with severity, file, and line. The same output plugs into most enterprise SARIF-consuming dashboards.

It also ships a --discover mode that scans known MCP client config locations on a machine (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf) in one pass, closing the "which MCP servers am I actually running" blind spot that most teams have no visibility into.

I also published a longer technical writeup covering the MCP threat model in more depth: indirect prompt injection through untrusted tool output, command injection patterns in real MCP server code, and how the detection rules map to specific attack vectors. Link in comments.

Feedback and issues welcome on the repo.

#security #mcp #opensource #python #devsecops
