"""MCP021 — a click handler dispatches a privileged action with no
`event.isTrusted` check.

Confirmed root-cause mechanism (Manifold Security, reported to Anthropic's
bug bounty program 2026-05-21; still unpatched against the shipped v1.0.80
as of 2026-07-07, corroborated by Bleeping Computer and The Hacker News):
Claude for Chrome's content-script click handler on claude.ai never checks
`event.isTrusted` before reading a clicked element's `data-task-id`
attribute and dispatching the associated agentic task (reading recent
Gmail, creating a calendar meeting, modifying Salesforce leads, ...). Any
other script with DOM access on the page — commonly another installed
browser extension, which routinely holds script access to claude.ai — can
construct the same element and dispatch a synthetic click event
(`element.dispatchEvent(new MouseEvent('click'))`), and the handler has no
way to tell it apart from a real user gesture. No CVE has been assigned;
Anthropic's internal ticket was marked "Resolved" without the fix (a single
`isTrusted` check) actually shipping across eight point releases.

This is a general web-security anti-pattern, not unique to that one
extension: any content script, extension popup, or browser-facing web app
that reads data off a clicked element and forwards it to a privileged sink
(extension messaging, a background script, an approve/grant/authorize call)
without checking `event.isTrusted` has the identical gap — a script can
forge the "user clicked this" signal a privileged action relies on.

Scoped narrow and high-signal, matching the rest of mcpscan's design: a
click listener registration, followed within a line window by *both*
(a) a read of the clicked element's own data (`.dataset.x` /
`getAttribute(...)`) and (b) a privileged dispatch (extension messaging, or
an approve/grant/authorize-named call) — with no `isTrusted` check anywhere
in that window. A handler that checks `event.isTrusted` before acting, or
that never reads element data at all (e.g. a purely cosmetic click
handler), never matches.
"""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from ..loaders import FileInfo, by_kind
from .base import Rule, register

_JS_EXTS = {".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}

_CLICK_LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"]click['\"]"
    r"|\.onclick\s*=\s*(?:function\b|\([^)]*\)\s*=>)"
)

# The handler reads data off the element that was actually clicked.
_ELEMENT_DATA_READ_RE = re.compile(r"\.dataset\.\w+|getAttribute\s*\(")

# ...and forwards it to something privileged: extension/background
# messaging, or a call that looks like it grants/approves/authorizes an
# action.
_PRIVILEGED_SINK_RE = re.compile(
    r"chrome\.runtime\.sendMessage\s*\("
    r"|browser\.runtime\.sendMessage\s*\("
    r"|\.postMessage\s*\("
    r"|\b(?:approve|grant|authoriz)\w*\s*\(",
    re.IGNORECASE,
)

_IS_TRUSTED_RE = re.compile(r"\.isTrusted\b")

_WINDOW = 30


@register
class UntrustedClickPrivilegedAction(Rule):
    id = "MCP021"
    name = "Click handler dispatches a privileged action with no event.isTrusted check"
    severity = Severity.HIGH
    owasp = "MCP07:2025"  # Insufficient Authentication & Authorization

    def check(self, files: List[FileInfo]) -> List[Finding]:
        out: List[Finding] = []
        for f in by_kind(files, "source"):
            if f.ext not in _JS_EXTS:
                continue
            lines = f.lines
            n = len(lines)
            for i, line in enumerate(lines):
                if not _CLICK_LISTENER_RE.search(line):
                    continue

                window = lines[i:min(i + _WINDOW, n)]
                window_text = "\n".join(window)
                if _IS_TRUSTED_RE.search(window_text):
                    continue
                if not _ELEMENT_DATA_READ_RE.search(window_text):
                    continue

                sink_idx = None
                for j, wline in enumerate(window):
                    if _PRIVILEGED_SINK_RE.search(wline):
                        sink_idx = i + j
                        break
                if sink_idx is None:
                    continue

                out.append(self.finding(
                    f, sink_idx + 1, lines[sink_idx],
                    title="Click handler dispatches a privileged action "
                          "with no event.isTrusted check",
                    detail=(
                        "This click handler reads data off the clicked "
                        "element and forwards it to a privileged sink "
                        "(extension messaging, or an approve/grant/"
                        "authorize call) without checking event.isTrusted "
                        "anywhere in the handler. Any other script with DOM "
                        "access on the page — commonly another installed "
                        "browser extension — can construct the same "
                        "element and dispatch a synthetic click event "
                        "(element.dispatchEvent(new MouseEvent('click'))), "
                        "and this handler has no way to tell it apart from "
                        "a real user gesture. This is the confirmed root "
                        "cause behind Claude for Chrome's still-unpatched "
                        "click-spoofing flaw (reported to Anthropic's bug "
                        "bounty 2026-05-21, confirmed still broken against "
                        "v1.0.80 on 2026-07-07 by Manifold Security). Check "
                        "event.isTrusted before reading or acting on "
                        "anything in the handler."
                    ),
                ))
        return out
