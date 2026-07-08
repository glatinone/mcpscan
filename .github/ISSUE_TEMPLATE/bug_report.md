---
name: Bug report
about: A rule misfired, crashed, or missed something it should have caught
title: ""
labels: bug
assignees: ""
---

**What happened**

A clear description of the bug: a false positive, a false negative, a crash, or
wrong output in a specific format (text/json/sarif).

**Rule ID (if applicable)**

e.g. `MCP004`. Run `mcpscan --list-rules` if you're not sure which rule fired.

**Minimal reproduction**

The smallest file or config snippet that reproduces the issue, plus the exact
command you ran:

```bash
mcpscan <path> <flags>
```

```
<the offending line(s) of code/config>
```

**Expected vs. actual**

What you expected `mcpscan` to report, and what it reported instead.

**Environment**

- mcpscan version: `mcpscan --version`
- Python version: `python --version`
- OS:
