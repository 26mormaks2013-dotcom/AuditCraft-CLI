"""Tests for auditcraft.core.report_builder and models."""

from __future__ import annotations

from pathlib import Path

import pytest

from auditcraft.core.report_builder import (
    build_report,
    build_report_from_file,
    load_summary,
    save_summary,
)
from auditcraft.models.issue import Finding, ReportSummary, Severity


@pytest.fixture()
def sample_summary() -> ReportSummary:
    return ReportSummary(
        project="Demo Protocol",
        auditor="Alice",
        findings=[
            Finding(
                title="Reentrancy in withdraw",
                severity=Severity.HIGH,
                description="External call before state update.",
                recommendation="Use checks-effects-interactions.",
                location="Vault.sol:42",
            ),
            Finding(
                title="Missing event",
                severity=Severity.LOW,
                description="State change without event.",
                recommendation="Emit an event.",
            ),
        ],
    )


def test_save_and_load_roundtrip(tmp_path: Path, sample_summary: ReportSummary) -> None:
    path = tmp_path / "audit_summary.json"
    save_summary(sample_summary, path)
    assert path.exists()

    loaded = load_summary(path)
    assert loaded.project == sample_summary.project
    assert loaded.auditor == sample_summary.auditor
    assert len(loaded.findings) == 2
    assert loaded.findings[0].severity is Severity.HIGH


def test_counts_by_severity(sample_summary: ReportSummary) -> None:
    counts = sample_summary.counts_by_severity()
    assert counts == {"high": 1, "low": 1}


def test_build_report_contains_key_sections(sample_summary: ReportSummary) -> None:
    md = build_report(sample_summary)
    assert "Demo Protocol" in md
    assert "Alice" in md
    assert "Reentrancy in withdraw" in md
    assert "Missing event" in md
    assert "high" in md
    assert "Vault.sol:42" in md


def test_build_report_from_file(tmp_path: Path, sample_summary: ReportSummary) -> None:
    path = tmp_path / "summary.json"
    save_summary(sample_summary, path)
    md = build_report_from_file(path)
    assert "Demo Protocol" in md
    assert "Reentrancy in withdraw" in md


def test_empty_findings_renders_marker() -> None:
    summary = ReportSummary(project="Empty", findings=[])
    md = build_report(summary)
    assert "Empty" in md
    assert "No findings" in md


def test_severity_alias_mapping() -> None:
    assert Severity("crit") is Severity.CRITICAL
    assert Severity("informational") is Severity.INFO
    assert Severity("optimization") is Severity.GAS


def test_finding_default_severity_is_medium() -> None:
    f = Finding(title="x")
    assert f.severity is Severity.MEDIUM
    assert f.location is None
