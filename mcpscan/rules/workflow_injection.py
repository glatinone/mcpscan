"""MCP015 / MCP016 — untrusted content flowing into GitHub Actions execution.

The first rule category to look at `.github/workflows/*.yml` rather than an MCP
server's own source or config. Motivated by `research/2026-07-14.md` Pain Radar
#1 and `research/2026-07-15.md`'s top compounding opportunity: the same root
cause (an agentic/automated CI workflow treats untrusted issue/PR/comment
content as instructions or code instead of data) has now been independently
disclosed across at least four vendors (Claude Code Action, Copilot, Gemini,
Codex "GitLost"). Both checks below are the two textbook, well-documented
GitHub Actions vulnerability classes that produce that same outcome, and both
are detectable as a line-window heuristic over the raw YAML text — no YAML
parser needed, consistent with mcpscan staying zero-dependency.

MCP015 — script injection: an attacker-controlled context expression (an issue
title, PR body, review comment, branch name, etc.) is interpolated directly as
`${{ ... }}` inside a `run:`/`script:` execution step instead of being passed
through an `env:` variable first and referenced as `$VAR`. GitHub's own
hardening guide documents this exact anti-pattern and its fix:
https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
A workflow that already follows the recommended env-var indirection never
matches this rule — the raw `${{ github.event... }}` form never appears inside
the execution step itself once it's been assigned to `env:` first.

MCP016 — "pwn request": a workflow triggers on `pull_request_target` (which
runs with the base repository's secrets and default token, even for a fork
PR) and then checks out the fork's own head commit (`actions/checkout` with
`ref: ${{ github.event.pull_request.head.sha }}` or `.head.ref`) — the fork's
code now executes with the base repo's trust level. See GitHub Security Lab,
"Keeping your GitHub Actions and workflows secure: Preventing pwn requests."

Both checks are deliberately conservative: they only fire on the raw
`${{ }}` interpolation / literal `ref:` shapes above, not on every possible
indirect path (e.g. an intermediate action re-exporting the same data under a
new name) — matching the rest of mcpscan's "high signal over recall" design
principle.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..findings import Finding, Severity
from ..loaders import FileInfo
from .base import Rule, register

_WORKFLOW_DIR = ".github/workflows/"

# Context expressions whose contents an attacker fully controls.
_UNTRUSTED_CONTEXTS = (
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.discussion_comment\.body",
    r"github\.head_ref",
    r"github\.event\.head_commit\.message",
)
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(?:" + "|".join(_UNTRUSTED_CONTEXTS) + r")[^}]*\}\}"
)

# The two YAML keys that hand raw text to a shell/JS interpreter.
_EXEC_KEY_RE = re.compile(r"^(\s*)(-\s+)?(run|script)\s*:\s*(.*)$")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?\s*$")


def _is_workflow_file(f: FileInfo) -> bool:
    return f.ext in (".yml", ".yaml") and _WORKFLOW_DIR in f.relpath


def _exec_block_ranges(lines: List[str]) -> List[Tuple[int, int]]:
    """Return 0-based, inclusive (start, end) line ranges holding run:/script: text.

    A `run: |`/`run: >` (or `script: |`) block scalar covers every following
    line indented deeper than the key itself; a single-line `run: <cmd>` value
    is a one-line range.
    """
    out: List[Tuple[int, int]] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _EXEC_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        key_indent = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
        rest = m.group(4).strip()
        if rest == "" or _BLOCK_SCALAR_RE.match(rest):
            j = i + 1
            last = i
            while j < n:
                line = lines[j]
                if line.strip() == "":
                    j += 1
                    continue
                indent = len(line) - len(line.lstrip(" "))
                if indent <= key_indent:
                    break
                last = j
                j += 1
            if last > i:
                out.append((i + 1, last))
            i = j
        else:
            out.append((i, i))
            i += 1
    return out


@register
class WorkflowScriptInjection(Rule):
    id = "MCP015"
    name = "Untrusted event content interpolated directly into a run/script step"
    severity = Severity.HIGH
    owasp = "MCP05:2025"  # Command Injection & Execution

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            for start, end in _exec_block_ranges(lines):
                for idx in range(start, end + 1):
                    line = lines[idx]
                    m = UNTRUSTED_CONTEXT_RE.search(line)
                    if not m:
                        continue
                    out.append(self.finding(
                        f, idx + 1, line,
                        title="Untrusted event content interpolated directly "
                              "into a shell step",
                        detail=f"{m.group(0)} is attacker-controlled (an issue/PR "
                               "title, body, comment, or branch name) and is "
                               "expanded directly into a run/script step, so its "
                               "contents execute as shell code. Pass it through an "
                               "env: variable first and reference it as $VAR in the "
                               "script instead of interpolating ${{ }} directly.",
                    ))
        return out


# --- MCP016 -----------------------------------------------------------------

_ON_KEY_RE = re.compile(r'^["\']?on["\']?\s*:')
_PULL_REQUEST_TARGET_RE = re.compile(r"(?:^|[\[\s,'\"])pull_request_target(?:$|[\]\s,:'\"])")
_CHECKOUT_RE = re.compile(r"uses:\s*actions/checkout@")
_PR_HEAD_REF_RE = re.compile(
    r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}"
)
_STEP_START_RE = re.compile(r"^(\s*)-\s")


def _triggers_on_pull_request_target(lines: List[str]) -> bool:
    in_on_block = False
    on_indent = 0
    for line in lines:
        stripped = line.strip()
        if not in_on_block and _ON_KEY_RE.match(stripped):
            in_on_block = True
            on_indent = len(line) - len(line.lstrip(" "))
            if _PULL_REQUEST_TARGET_RE.search(stripped):
                return True
            continue
        if in_on_block:
            if stripped == "":
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= on_indent:
                in_on_block = False
                continue
            if _PULL_REQUEST_TARGET_RE.search(line):
                return True
    return False


@register
class PwnRequestCheckout(Rule):
    id = "MCP016"
    name = "pull_request_target workflow checks out the fork's own head commit"
    severity = Severity.CRITICAL
    owasp = "MCP04:2025"  # Software Supply Chain Attacks & Dependency Tampering

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            if not _triggers_on_pull_request_target(lines):
                continue

            n = len(lines)
            for i, line in enumerate(lines):
                if not _CHECKOUT_RE.search(line):
                    continue
                step_indent = self._step_indent(lines, i)
                for j in range(i + 1, min(i + 12, n)):
                    probe = lines[j]
                    if probe.strip() and _STEP_START_RE.match(probe):
                        probe_indent = len(probe) - len(probe.lstrip(" "))
                        if probe_indent <= step_indent:
                            break
                    if _PR_HEAD_REF_RE.search(probe):
                        out.append(self.finding(
                            f, j + 1, probe,
                            title="pull_request_target workflow checks out "
                                  "untrusted fork code",
                            detail="This workflow triggers on pull_request_target "
                                   "(runs with the base repository's secrets and "
                                   "write-scoped token, even for a fork PR) and "
                                   "checks out the PR's own head commit — the "
                                   "fork's code now executes with the base repo's "
                                   "trust level. Switch to the pull_request "
                                   "trigger, or gate this job behind a required "
                                   "reviewer/environment before checkout runs.",
                        ))
                        break
        return out

    @staticmethod
    def _step_indent(lines: List[str], idx: int) -> int:
        for k in range(idx, -1, -1):
            if _STEP_START_RE.match(lines[k]):
                return len(lines[k]) - len(lines[k].lstrip(" "))
        return len(lines[idx]) - len(lines[idx].lstrip(" "))
