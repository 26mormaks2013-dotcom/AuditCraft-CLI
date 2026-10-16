"""Smoke tests for the AuditCraft CLI via CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from auditcraft.main import app

runner = CliRunner()


SOLIDITY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Demo {
    function f(address a) external {}
}
"""


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "AuditCraft" in result.stdout
    assert "0.1.0" in result.stdout


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scope" in result.stdout
    assert "report" in result.stdout
    assert "check" in result.stdout


def test_scope_json(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text(SOLIDITY, encoding="utf-8")
    result = runner.invoke(app, ["scope", str(tmp_path), "--json"])
    assert result.exit_code == 0
    # CliRunner обгортає JSON у print_json(); дістаємо перший JSON-об'єкт
    start = result.stdout.find("{")
    assert start >= 0
    payload = json.loads(result.stdout[start:])
    assert payload["files"] == 1
    assert payload["nsloc"] >= 1


def test_check_json(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text(SOLIDITY, encoding="utf-8")
    result = runner.invoke(app, ["check", str(tmp_path), "--json"])
    assert result.exit_code == 0
    start = result.stdout.find("{")
    assert start >= 0
    payload = json.loads(result.stdout[start:])
    assert "findings" in payload
    assert "counts" in payload


def test_check_bad_min_severity(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text(SOLIDITY, encoding="utf-8")
    result = runner.invoke(app, ["check", str(tmp_path), "--min-severity", "bogus"])
    assert result.exit_code == 2
    combined = (result.stdout or "") + (result.stderr or "")
    assert "Invalid" in combined


def test_report_init_add_build(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    report_md = tmp_path / "REPORT.md"

    r1 = runner.invoke(
        app,
        ["report", "init", "Demo", "--auditor", "Alice", "--output", str(summary)],
    )
    assert r1.exit_code == 0
    assert summary.exists()

    r2 = runner.invoke(
        app,
        [
            "report",
            "add",
            "Reentrancy",
            "--severity",
            "high",
            "--description",
            "External call before state update.",
            "--recommendation",
            "Use CEI.",
            "--summary",
            str(summary),
            "--non-interactive",
        ],
    )
    assert r2.exit_code == 0

    r3 = runner.invoke(
        app,
        ["report", "build", "--summary", str(summary), "--output", str(report_md)],
    )
    assert r3.exit_code == 0
    assert report_md.exists()
    text = report_md.read_text(encoding="utf-8")
    assert "Demo" in text
    assert "Reentrancy" in text
