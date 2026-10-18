"""Tests for auditcraft.core.contest_export."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from auditcraft.core.contest_export import export_findings
from auditcraft.core.static_checker import run_checks


VULN_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Bad {
    function kill() external { selfdestruct(payable(msg.sender)); }
}
"""


def _result_with_findings(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    return run_checks(src)


def test_export_creates_expected_zip_layout(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    assert result.findings, "fixture must trigger at least one finding"
    out = tmp_path / "out.zip"
    export_findings(result, out, platform="sherlock", project="Test Project")
    assert out.exists()
    names = zipfile.ZipFile(out).namelist()
    assert "sherlock/summary.md" in names
    assert "sherlock/findings.json" in names
    assert any(n.startswith("sherlock/H-") for n in names), names


def test_export_finding_markdown_has_sections(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    out = tmp_path / "out.zip"
    export_findings(result, out, platform="sherlock")
    with zipfile.ZipFile(out) as zf:
        h_files = [n for n in zf.namelist() if n.startswith("sherlock/H-")]
        assert h_files
        body = zf.read(h_files[0]).decode("utf-8")
    assert "## Vulnerability Detail" in body
    assert "## Impact" in body
    assert "## Code Snippet" in body
    assert "## Tool used" in body
    assert "## Recommendation" in body


def test_export_manifest_json_fields(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    out = tmp_path / "out.zip"
    export_findings(result, out, platform="cantina", project="Proj X")
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("cantina/findings.json").decode("utf-8"))
    assert manifest["platform"] == "cantina"
    assert manifest["project"] == "Proj X"
    assert manifest["total_findings"] == len(result.findings)
    assert "files_scanned" in manifest
    assert isinstance(manifest["counts"], dict)


def test_export_platform_prefix_matches_argument(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    out = tmp_path / "out.zip"
    export_findings(result, out, platform="code4rena")
    names = zipfile.ZipFile(out).namelist()
    assert any(n.startswith("code4rena/") for n in names)
    assert all(n.startswith("code4rena/") for n in names)


def test_export_unknown_platform_raises(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    with pytest.raises(ValueError):
        export_findings(result, tmp_path / "out.zip", platform="totally-unknown")


def test_export_summary_md_contains_counts(tmp_path: Path) -> None:
    result = _result_with_findings(tmp_path)
    out = tmp_path / "out.zip"
    export_findings(result, out, platform="sherlock", project="Demo")
    with zipfile.ZipFile(out) as zf:
        summary = zf.read("sherlock/summary.md").decode("utf-8")
    assert "Demo" in summary
    assert "Total findings" in summary
    assert "Counts by group" in summary
