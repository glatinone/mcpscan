"""Core data model: severities, findings, and the aggregated report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    """Ordered so comparisons work: CRITICAL > HIGH > ... > INFO."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{name}' (choose: {valid})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single issue discovered by a rule."""

    rule_id: str            # stable id, e.g. "MCP001"
    title: str              # short human summary
    severity: Severity
    path: str               # file the finding lives in (relative to scan root)
    line: int = 0           # 1-based line number, 0 if not applicable
    detail: str = ""        # longer explanation / remediation hint
    snippet: str = ""       # the offending text, trimmed

    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass
class Report:
    """Aggregates findings across a scan and answers questions about them."""

    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    suppressed: int = 0
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def at_or_above(self, threshold: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity >= threshold]

    def highest(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def counts(self) -> dict:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def sorted(self) -> List[Finding]:
        # Most severe first, then by file/line for stable output.
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.path, f.line, f.rule_id),
        )
