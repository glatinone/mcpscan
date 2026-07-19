"""MCP015 / MCP016 / MCP017 / MCP019 — untrusted content flowing into GitHub Actions.

The first rule category to look at `.github/workflows/*.yml` rather than an MCP
server's own source or config. Motivated by `research/2026-07-14.md` Pain Radar
#1 and `research/2026-07-15.md`'s top compounding opportunity: the same root
cause (an agentic/automated CI workflow treats untrusted issue/PR/comment
content as instructions or code instead of data) has now been independently
disclosed across at least four vendors (Claude Code Action, Copilot, Gemini,
Codex "GitLost"). All three checks below are detectable as a line-window
heuristic over the raw YAML text — no YAML parser needed, consistent with
mcpscan staying zero-dependency.

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

MCP017 — identity-based-trust / excess-scope reachability, the pattern
`research/2026-07-16.md`'s top compounding opportunity named "Cordyceps": a
2026-07 disclosure scanning ~30,000 high-impact repositories found 300+
confirmed exploitable on this exact shape (workflows granting a
PR/issue-triggered job more permission than it needs, with no identity check
gating it). Deliberately narrower than the "model every bot's trust config"
version deferred from v0.11.0 (`backlog.md`/`projects/mcpscan.md` TODO):
instead of guessing what config key means "trust this actor" per third-party
Action, this checks the generic, action-agnostic shape Cordyceps actually
confirmed — a workflow triggered by untrusted content (`pull_request_target`,
`issue_comment`, `issues`, `discussion`, `discussion_comment`) that also
references a *custom* secret (`${{ secrets.SOMETHING }}`, not the auto-scoped
`GITHUB_TOKEN` — that one is already governed by the `permissions:` block, a
distinct mechanism MCP016 already reasons about) with neither of the two
GitHub-documented gates present anywhere in the file: a protected
`environment:` (requires manual reviewer approval before the job's secrets
become available) or an explicit actor/author-association check (e.g.
`github.event.pull_request.author_association` compared against a trusted
list, or a `github.actor` allowlist). Custom secrets aren't scoped by
`permissions:` at all, so that block alone doesn't make this safe — hence
checking for the two mechanisms that actually do.

MCP019 — `workflow_run` artifact reachability: a workflow triggers on
`workflow_run` (which runs in the base repository's context — with its
default `GITHUB_TOKEN`, at whatever scope the repo/org leaves that token by
default — even when the triggering run came from a fork PR) and downloads an
artifact produced by that triggering run (`actions/download-artifact` or the
common third-party `dawidd6/action-download-artifact`, referencing
`github.event.workflow_run.id`), with no `permissions:` block anywhere in the
file restricting the token away from write access. This closes both
remaining documented GitHub Actions classes noted in the backlog as one rule
rather than two: the artifact-reachability shape itself, and "no explicit
`permissions:` block at all" folded in as the gate condition, since an absent
`permissions:` block leaves exactly the same broad default-token exposure a
write-scoped one would. A workflow that sets `permissions:` to read-only (or
`{}`) anywhere in the file, at any level, suppresses the finding — file-level
granularity, not job-level, the same known tradeoff MCP017 already documents
for its own gate check.

All checks are deliberately conservative: they only fire on the literal
shapes documented above, not on every possible indirect path (e.g. an
intermediate action re-exporting the same data under a new name, or a
job-level `environment:`/actor/`permissions:` check this file-level scan
can't attribute to the specific job that uses the secret or artifact) —
matching the rest of mcpscan's "high signal over recall" design principle.
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


def _step_indent(lines: List[str], idx: int) -> int:
    """Return the indent of the step (`- name:`/`- uses:`/`- run:`) containing line idx."""
    for k in range(idx, -1, -1):
        if _STEP_START_RE.match(lines[k]):
            return len(lines[k]) - len(lines[k].lstrip(" "))
    return len(lines[idx]) - len(lines[idx].lstrip(" "))


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
                step_indent = _step_indent(lines, i)
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


# --- MCP017 -----------------------------------------------------------------

_UNTRUSTED_TRIGGER_RE = re.compile(
    r"(?:^|[\[\s,'\"])"
    r"(?:pull_request_target|issue_comment|issues|discussion_comment|discussion)"
    r"(?:$|[\]\s,:'\"])"
)
_CUSTOM_SECRET_RE = re.compile(
    r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+"
)
_ENVIRONMENT_KEY_RE = re.compile(r"^\s*environment\s*:", re.MULTILINE)
_ACTOR_GATE_RE = re.compile(r"author_association|github\.actor\b")


def _on_block_text(lines: List[str]) -> str:
    """Return the raw text of the `on:` trigger block (key line included)."""
    out: List[str] = []
    in_on_block = False
    on_indent = 0
    for line in lines:
        stripped = line.strip()
        if not in_on_block and _ON_KEY_RE.match(stripped):
            in_on_block = True
            on_indent = len(line) - len(line.lstrip(" "))
            out.append(line)
            continue
        if in_on_block:
            if stripped == "":
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= on_indent:
                break
            out.append(line)
    return "\n".join(out)


@register
class UntrustedTriggerSecretReachability(Rule):
    id = "MCP017"
    name = ("Untrusted-trigger workflow reaches a custom secret with no "
            "environment or identity gate")
    severity = Severity.HIGH
    owasp = "MCP02:2025"  # Privilege Escalation via Scope Creep

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            if not _UNTRUSTED_TRIGGER_RE.search(_on_block_text(lines)):
                continue

            text = "\n".join(lines)
            if _ENVIRONMENT_KEY_RE.search(text) or _ACTOR_GATE_RE.search(text):
                continue

            for i, line in enumerate(lines):
                if not _CUSTOM_SECRET_RE.search(line):
                    continue
                out.append(self.finding(
                    f, i + 1, line,
                    title="Untrusted-trigger workflow reaches a custom "
                          "secret with no gate",
                    detail="This workflow can be triggered by untrusted "
                           "content (an issue, PR, or comment from anyone, "
                           "not just a repo collaborator) and this step "
                           "references a custom secret. Unlike GITHUB_TOKEN, "
                           "custom secrets aren't scoped by a permissions: "
                           "block, so an unscoped permissions setup doesn't "
                           "help here. Gate this job behind a protected "
                           "environment: (Settings > Environments, require "
                           "reviewers) or an explicit actor/author_association "
                           "check before the secret is used, or switch to the "
                           "pull_request trigger if the job doesn't actually "
                           "need write-scoped secrets.",
                ))
        return out


# --- MCP019 -----------------------------------------------------------------

_WORKFLOW_RUN_TRIGGER_RE = re.compile(
    r"(?:^|[\[\s,'\"])workflow_run(?:$|[\]\s,:'\"])"
)
_DOWNLOAD_ARTIFACT_RE = re.compile(
    r"uses:\s*(?:actions/download-artifact|dawidd6/action-download-artifact)@"
)
_TRIGGERING_RUN_ID_RE = re.compile(
    r"run[-_]id\s*:\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}"
)
_PERMISSIONS_KEY_RE = re.compile(r"^(\s*)permissions\s*:\s*(.*)$")


def _has_restrictive_permissions_gate(lines: List[str]) -> bool:
    """True if the file sets an explicit `permissions:` (anywhere, any level)
    that grants no write scope. False if `permissions:` is absent entirely,
    or any occurrence grants a write scope (including `write-all`) — either
    case leaves the broad/default `GITHUB_TOKEN` scope in play.
    """
    found_permissions_key = False
    i = 0
    n = len(lines)
    while i < n:
        m = _PERMISSIONS_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        found_permissions_key = True
        key_indent = len(m.group(1))
        inline_value = m.group(2).strip()
        if inline_value:
            if "write" in inline_value.lower():
                return False
            i += 1
            continue
        j = i + 1
        block_lines: List[str] = []
        while j < n:
            probe = lines[j]
            if probe.strip() == "":
                j += 1
                continue
            indent = len(probe) - len(probe.lstrip(" "))
            if indent <= key_indent:
                break
            block_lines.append(probe)
            j += 1
        if "write" in "\n".join(block_lines).lower():
            return False
        i = j
    return found_permissions_key


@register
class WorkflowRunArtifactReachability(Rule):
    id = "MCP019"
    name = ("workflow_run workflow downloads the triggering run's artifact "
            "with no restrictive permissions gate")
    severity = Severity.HIGH
    owasp = "MCP02:2025"  # Privilege Escalation via Scope Creep

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            if not _WORKFLOW_RUN_TRIGGER_RE.search(_on_block_text(lines)):
                continue
            if _has_restrictive_permissions_gate(lines):
                continue

            n = len(lines)
            for i, line in enumerate(lines):
                if not _DOWNLOAD_ARTIFACT_RE.search(line):
                    continue
                step_indent = _step_indent(lines, i)
                for j in range(i + 1, min(i + 12, n)):
                    probe = lines[j]
                    if probe.strip() and _STEP_START_RE.match(probe):
                        probe_indent = len(probe) - len(probe.lstrip(" "))
                        if probe_indent <= step_indent:
                            break
                    if _TRIGGERING_RUN_ID_RE.search(probe):
                        out.append(self.finding(
                            f, j + 1, probe,
                            title="workflow_run job downloads the triggering "
                                  "run's artifact with no permissions gate",
                            detail="This workflow triggers on workflow_run, "
                                   "which runs in the base repository's "
                                   "context with the default GITHUB_TOKEN "
                                   "even when the triggering run came from a "
                                   "fork PR, and downloads an artifact "
                                   "produced by that untrusted triggering "
                                   "run. With no permissions: block "
                                   "restricting the token to read-only "
                                   "anywhere in this file, whatever this job "
                                   "does with the artifact runs at the base "
                                   "repo's full default privilege. Add a "
                                   "permissions: block scoped to read-only "
                                   "(or only the specific write scope "
                                   "actually needed), and treat the "
                                   "artifact's contents as untrusted — don't "
                                   "execute it directly.",
                        ))
                        break
        return out
