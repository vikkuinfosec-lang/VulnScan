"""Core data models shared across all check modules and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered from most to least urgent."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        """Lower rank = more severe. Used for sorting findings."""
        return {"High": 0, "Medium": 1, "Low": 2, "Info": 3}[self.value]


@dataclass
class Finding:
    """A single detected issue.

    id:          stable short code, e.g. "HDR-001", used for dedup/testing.
    title:       one-line summary, e.g. "Missing Content-Security-Policy header".
    severity:    Severity enum.
    category:    which check module produced it, e.g. "Headers", "TLS", "Ports", "Misconfig".
    description: what the issue is and why it matters.
    evidence:    the concrete observation that triggered this finding (header value,
                 cert expiry date, open port number, etc.).
    remediation: concrete guidance on how to fix it.
    references:  optional list of URLs for further reading (OWASP, MDN, RFCs).
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregate result of a full scan run, ready for reporting."""

    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.category, f.id))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)
