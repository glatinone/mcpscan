"""MCP015 / MCP016 / MCP017 / MCP019 / MCP020: untrusted content and excess
token scope in GitHub Actions.

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

MCP019: `workflow_run` token/artifact reuse. A workflow triggers on
`workflow_run` (which always runs the *base* branch's copy of the workflow
file, with the base repository's default `GITHUB_TOKEN` and secrets, even
when the triggering run came from a fork PR; GitHub's own docs on
`workflow_run` describe this trust boundary explicitly), and then either (a)
checks out the triggering run's own commit/branch
(`github.event.workflow_run.head_sha`/`.head_branch`) via `actions/checkout`,
or (b) downloads an artifact that run produced
(`actions/download-artifact`/`dawidd6/action-download-artifact` referencing
`github.event.workflow_run.id`), the documented "artifact poisoning"
pattern GitHub Security Lab and GitHub's own hardening guide both describe.
Either way, content an attacker fully controlled (by opening the fork PR
that produced the triggering run) is now checked out or downloaded inside a
job that still holds the base repo's privileged token, the same "pwn
request" shape as MCP016, just reached via `workflow_run` instead of
`pull_request_target` directly. Deliberately not conditioned on the file's
`permissions:` block (mirrors MCP016, which doesn't check it either): once
untrusted code or a script is on disk in a privileged job, a scoped-down
token doesn't stop it from reading secrets out of the job's own environment
or tampering with the build. The fix is not reaching the untrusted
ref/artifact in the first place, not narrowing what the token can do
afterward.

MCP020: `GITHUB_TOKEN` over-permissioning. A workflow has no explicit
`permissions:` key anywhere in the file (top-level or job-level), so its
token is left at whatever the repository/organization default grants,
still read-write on every scope for any org created before GitHub flipped
the new-org default to read-only in February 2023, and for older orgs that
never revisited the setting. This is a "missing thing" check, not a "found
something bad" one, and the wrong kind of false positive is expensive here:
plenty of workflows correctly omit `permissions:` because they truly need no
elevated scope (this project's own `ci.yml` is exactly that: checkout, install,
run tests, dogfood-scan itself, nothing that writes anywhere). So the rule
requires a second, independent condition before it fires: the workflow must
also contain a recognizable *write* action or command, publishing a
release, pushing a commit, commenting on or merging a PR/issue, or calling
the GitHub REST API with a write HTTP verb. A workflow with no
`permissions:` block that never does any of those stays quiet, the same way
MCP017 stays quiet on a `GITHUB_TOKEN`-only workflow. `actions/github-script`
calling a write-shaped REST/GraphQL method is a known, deliberate gap here,
detecting that would mean parsing the JS callback body, not just a YAML line
window; worth widening if real-world scans surface it as the dominant shape.

All checks are deliberately conservative: they only fire on the literal
shapes documented above, not on every possible indirect path (e.g. an
intermediate action re-exporting the same data under a new name, or a
job-level `environment:`/actor/`permissions:` check this file-level scan
can't attribute to the specific job that uses the secret or artifact),
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
_WORKFLOW_RUN_HEAD_REF_RE = re.compile(
    r"ref:\s*\$\{\{\s*github\.event\.workflow_run\.head_(?:sha|branch)\s*\}\}"
)


def _lookahead_in_step(lines: List[str], step_idx: int, pattern: "re.Pattern[str]",
                        max_ahead: int = 12) -> "Tuple[int, str] | None":
    """Search up to *max_ahead* lines after the step starting at *step_idx*
    for *pattern*, stopping at the next sibling step boundary so an unrelated
    later step can't false-positive. Returns (0-based line idx, text) or None.
    """
    step_indent = _step_indent(lines, step_idx)
    n = len(lines)
    for j in range(step_idx + 1, min(step_idx + 1 + max_ahead, n)):
        probe = lines[j]
        if probe.strip() and _STEP_START_RE.match(probe):
            probe_indent = len(probe) - len(probe.lstrip(" "))
            if probe_indent <= step_indent:
                break
        if pattern.search(probe):
            return j, probe
    return None


@register
class WorkflowRunArtifactReuse(Rule):
    id = "MCP019"
    name = ("workflow_run workflow checks out or downloads content from the "
            "triggering (untrusted) run")
    severity = Severity.CRITICAL
    owasp = "MCP04:2025"  # Software Supply Chain Attacks & Dependency Tampering

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            if not _WORKFLOW_RUN_TRIGGER_RE.search(_on_block_text(lines)):
                continue

            for i, line in enumerate(lines):
                if _CHECKOUT_RE.search(line):
                    hit = _lookahead_in_step(lines, i, _WORKFLOW_RUN_HEAD_REF_RE)
                    if hit is None:
                        continue
                    j, probe = hit
                    out.append(self.finding(
                        f, j + 1, probe,
                        title="workflow_run workflow checks out the "
                              "triggering run's own untrusted commit",
                        detail="This workflow triggers on workflow_run, which "
                               "runs the base branch's copy of this file with "
                               "the base repository's secrets and token even "
                               "when the triggering run came from a fork PR, "
                               "and checks out that run's own head commit/"
                               "branch. Building or testing that checkout now "
                               "executes attacker-controlled code with the "
                               "privileged token. Check out the base ref "
                               "instead, or, if the fork's code genuinely "
                               "needs to run, gate the job behind a required "
                               "reviewer/environment first.",
                    ))
                elif _DOWNLOAD_ARTIFACT_RE.search(line):
                    hit = _lookahead_in_step(lines, i, _TRIGGERING_RUN_ID_RE)
                    if hit is None:
                        continue
                    j, probe = hit
                    out.append(self.finding(
                        f, j + 1, probe,
                        title="workflow_run workflow downloads an artifact "
                              "from the triggering (untrusted) run",
                        detail="This workflow triggers on workflow_run and "
                               "downloads an artifact produced by the run "
                               "that triggered it, while still holding the "
                               "base repository's token/secrets, the "
                               "documented 'artifact poisoning' pattern. If "
                               "the triggering workflow can run on a fork PR, "
                               "the artifact's contents are "
                               "attacker-controlled. Never extract-and-execute "
                               "it directly; validate its contents first, or "
                               "use it only as inert data (e.g. a test report "
                               "to display, not a script to run).",
                    ))
        return out


# --- MCP020 -----------------------------------------------------------------

_PERMISSIONS_KEY_RE = re.compile(r"^\s*permissions\s*:", re.MULTILINE)

# A deliberately narrow set of shapes that unambiguously *write* to GitHub
# using the workflow's token. Chosen so a genuinely read-only workflow (this
# project's own ci.yml: checkout, install, run tests, dogfood-scan itself)
# never matches any of them. That is the second, independent condition that
# keeps this "missing permissions:" check from firing on every workflow that
# simply doesn't need one.
_WRITE_ACTIONS = (
    r"softprops/action-gh-release@",
    r"actions/create-release@",
    r"peter-evans/create-pull-request@",
    r"peter-evans/create-or-update-comment@",
    r"marocchino/sticky-pull-request-comment@",
    r"stefanzweifel/git-auto-commit-action@",
    r"endbug/add-and-commit@",
    r"ad-m/github-push-action@",
)
_WRITE_ACTION_RE = re.compile(
    r"uses:\s*(?:" + "|".join(_WRITE_ACTIONS) + r")", re.IGNORECASE
)
_GIT_PUSH_RE = re.compile(r"(?:^|[\s|;&])git\s+push\b")
_GH_WRITE_CLI_RE = re.compile(
    r"\bgh\s+(?:"
    r"release\s+create"
    r"|pr\s+(?:comment|merge|review|edit|close)"
    r"|issue\s+(?:comment|close|edit)"
    r"|workflow\s+run"
    r"|api\s+\S+.*-X\s*(?:POST|PUT|PATCH|DELETE)"
    r")",
    re.IGNORECASE,
)
_CURL_RE = re.compile(r"\bcurl\b")
_HTTP_WRITE_METHOD_RE = re.compile(r"-X\s*(?:POST|PUT|PATCH|DELETE)", re.IGNORECASE)
_GITHUB_API_HOST_RE = re.compile(r"api\.github\.com")


def _write_signal(lines: List[str]) -> "Tuple[int, str] | None":
    """Return the (1-based line, text) of the first recognizable write
    action or command, or None. See the module docstring for why this list
    is narrow on purpose."""
    for i, line in enumerate(lines, start=1):
        if _WRITE_ACTION_RE.search(line):
            return i, line
        if _GIT_PUSH_RE.search(line):
            return i, line
        if _GH_WRITE_CLI_RE.search(line):
            return i, line
        if (_CURL_RE.search(line) and _HTTP_WRITE_METHOD_RE.search(line)
                and _GITHUB_API_HOST_RE.search(line)):
            return i, line
    return None


@register
class MissingPermissionsBlock(Rule):
    id = "MCP020"
    name = "Workflow writes to GitHub with no explicit permissions: block"
    severity = Severity.MEDIUM
    owasp = "MCP02:2025"  # Privilege Escalation via Scope Creep

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            if not _is_workflow_file(f):
                continue
            lines = f.lines
            if _PERMISSIONS_KEY_RE.search("\n".join(lines)):
                continue  # an explicit choice was made, whatever it grants

            hit = _write_signal(lines)
            if hit is None:
                continue
            i, line = hit
            out.append(self.finding(
                f, i, line,
                title="Workflow writes to GitHub with no explicit "
                      "permissions: block",
                detail="This workflow has no top-level or job-level "
                       "permissions: key anywhere, so its GITHUB_TOKEN gets "
                       "whatever the repository or organization default "
                       "grants. For any org created before GitHub's "
                       "February 2023 default change (or one that reverted "
                       "the setting), that default is read/write on every "
                       "scope. This workflow writes to GitHub (a release, "
                       "PR/issue comment, push, or API call), so add an "
                       "explicit permissions: block scoped to only what "
                       "this job actually needs (e.g. contents: write, or "
                       "pull-requests: write) instead of relying on "
                       "whatever the org default happens to be today.",
            ))
        return out
