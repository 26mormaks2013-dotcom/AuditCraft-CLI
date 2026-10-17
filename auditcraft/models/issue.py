"""Pydantic v2 models used across AuditCraft.

Two distinct finding shapes coexist here:

* :class:`Finding` — auditor-authored entries used by ``auditcraft report``.
* :class:`CheckFinding` — auto-generated entries from ``auditcraft check``.

Severity is a single string enum that accepts both severity vocabularies
(``high|medium|low|nc|gas`` and ``info|warning|critical``) plus common aliases.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Canonical severities plus aliases for report vs. check vocabularies."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NC = "nc"
    GAS = "gas"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object) -> Severity | None:
        if not isinstance(value, str):
            return None
        key = value.strip().lower()
        aliases = {
            "crit": "critical",
            "med": "medium",
            "warn": "warning",
            "informational": "info",
            "none": "nc",
            "non-critical": "nc",
            "noncritical": "nc",
            "optimization": "gas",
            "optimizations": "gas",
        }
        key = aliases.get(key, key)
        for member in cls:
            if member.value == key:
                return member
        return None


class Finding(BaseModel):
    """Auditor-authored finding (used by ``auditcraft report``)."""

    title: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    recommendation: str = ""
    location: str | None = None


class CheckFinding(BaseModel):
    """Auto-generated finding produced by the static checker."""

    rule_id: str
    severity: Severity
    path: str
    line: int
    message: str


# Backwards-compatible alias used by some tests / external callers.
Issue = CheckFinding


class CheckResult(BaseModel):
    """Aggregate output from a static-check run."""

    findings: list[CheckFinding] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0


class ReportSummary(BaseModel):
    """Top-level object persisted as ``audit_summary.json``."""

    project: str
    auditor: str | None = None
    findings: list[Finding] = Field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        """Return non-zero counts keyed by severity in a stable order."""
        order = [
            "critical",
            "high",
            "medium",
            "low",
            "warning",
            "info",
            "nc",
            "gas",
        ]
        counts: dict[str, int] = {k: 0 for k in order}
        for finding in self.findings:
            key = finding.severity.value
            counts[key] = counts.get(key, 0) + 1
        return {k: v for k, v in counts.items() if v > 0}
