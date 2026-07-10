"""Render a Report as human text, JSON, or SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Dict

from .findings import Report, Severity

# ANSI colors keyed by severity.
_COLOR = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def render_text(report: Report, color: bool = True) -> str:
    def c(s: str, code: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    lines = []
    findings = report.sorted()
    for f in findings:
        tag = c(f" {f.severity.label.upper():^8} ", _COLOR[f.severity])
        owasp = c(f" [{f.owasp}]", _DIM) if f.owasp else ""
        lines.append(f"{tag} {c(f.rule_id, _BOLD)}  {f.title}{owasp}")
        lines.append(f"          {c(f.location(), _DIM)}")
        if f.snippet:
            lines.append(f"          {c('> ' + f.snippet, _DIM)}")
        if f.detail:
            lines.append(f"          {f.detail}")
        lines.append("")

    counts = report.counts()
    summary = "  ".join(
        c(f"{counts[s.label]} {s.label}", _COLOR[s])
        for s in reversed(Severity) if counts[s.label]
    ) or c("no findings", "\033[92m")

    suffix = f" ({report.suppressed} suppressed)" if report.suppressed else ""
    header = (c("mcpscan", _BOLD)
              + f"  scanned {report.files_scanned} files in {report.root}{suffix}")
    footer = f"{_BOLD if color else ''}Summary:{_RESET if color else ''} {summary}"
    body = "\n".join(lines) if findings else c("  Clean — no issues found.\n", "\033[92m")
    err = ""
    if report.errors:
        err = "\n" + "\n".join("  ! " + e for e in report.errors)
    return f"{header}\n\n{body}\n{footer}{err}"


def render_json(report: Report) -> str:
    payload: Dict = {
        "tool": "mcpscan",
        "root": report.root,
        "files_scanned": report.files_scanned,
        "suppressed": report.suppressed,
        "counts": report.counts(),
        "errors": report.errors,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.label,
                "path": f.path,
                "line": f.line,
                "detail": f.detail,
                "snippet": f.snippet,
                "owasp": f.owasp,
            }
            for f in report.sorted()
        ],
    }
    return json.dumps(payload, indent=2)


# SARIF severity maps onto a small set of levels.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _sarif_rules(findings) -> list:
    """SARIF ``tool.driver.rules`` entries for the rule ids seen in *findings*.

    Shared by :func:`render_sarif` and ``discover.render_discovery_sarif`` so
    the rule-metadata shape (including the OWASP tag lookup) only lives once.
    """
    # First OWASP tag seen per rule id — every finding from one rule carries
    # the same tag, so any occurrence works as the rule-level lookup.
    owasp_by_rule: Dict[str, str] = {}
    for f in findings:
        if f.owasp:
            owasp_by_rule.setdefault(f.rule_id, f.owasp)
    rule_ids = sorted({f.rule_id for f in findings})
    return [
        {
            "id": rid,
            **({"properties": {"tags": [owasp_by_rule[rid]],
                                "owaspMcpTop10": owasp_by_rule[rid]}}
               if rid in owasp_by_rule else {}),
        }
        for rid in rule_ids
    ]


def _sarif_result(f, uri: str) -> Dict:
    """One SARIF ``results[]`` entry for finding *f*, located at *uri*.

    *uri* is a separate parameter (not always ``f.path``) so discovery mode
    can point results at the full client-config path instead of the bare
    filename a single-file scan records.
    """
    return {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{f.title}. {f.detail}".strip()},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, f.line)},
            }
        }],
        **({"properties": {"owaspMcpTop10": f.owasp}} if f.owasp else {}),
    }


def render_sarif(report: Report) -> str:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpscan",
                "informationUri": "https://github.com/glatinone/mcpscan",
                "rules": _sarif_rules(report.findings),
            }},
            "results": [_sarif_result(f, f.path) for f in report.sorted()],
        }],
    }
    return json.dumps(sarif, indent=2)


def render(report: Report, fmt: str, color: bool = True) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    return render_text(report, color=color)
