"""Tests for auditcraft.core.diff_engine."""

from __future__ import annotations

from pathlib import Path

from auditcraft.core.diff_engine import build_delta, render_markdown


SAFE_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Safe {
    uint256 public value;
    function setValue(uint256 v) external { value = v; }
}
"""

VULN_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Bad {
    function kill() external { selfdestruct(payable(msg.sender)); }
}
"""


FLOATING = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Foo {}
"""


def test_build_delta_identical_trees(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "a.sol").write_text(SAFE_CONTRACT, encoding="utf-8")
    (new / "a.sol").write_text(SAFE_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert report.total_files_changed == 0
    assert report.files_added == []
    assert report.files_removed == []
    assert report.files_modified == []
    assert report.new == []
    assert report.fixed == []


def test_build_delta_file_removed(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert len(report.files_removed) == 1
    assert report.files_removed[0].path == "bad.sol"
    assert report.files_removed[0].status == "removed"
    assert "kill" in report.files_removed[0].functions_removed


def test_build_delta_file_added(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (new / "added.sol").write_text(SAFE_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert len(report.files_added) == 1
    assert report.files_added[0].path == "added.sol"
    assert report.files_added[0].status == "added"
    assert "setValue" in report.files_added[0].functions_added


def test_build_delta_file_modified(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "a.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract A { function a() external {} }\n",
        encoding="utf-8",
    )
    (new / "a.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\ncontract A { function a() external {} function b() external {} }\n",
        encoding="utf-8",
    )
    report = build_delta(old, new)
    assert len(report.files_modified) == 1
    assert "b" in report.files_modified[0].functions_added


def test_build_delta_fixes_detected_when_vuln_removed(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert any(f.rule_id == "SC003" for f in report.fixed)
    assert not any(f.rule_id == "SC003" for f in report.new)


def test_build_delta_new_findings_detected(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (new / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert any(f.rule_id == "SC003" for f in report.new)
    assert not any(f.rule_id == "SC003" for f in report.fixed)


def test_build_delta_still_open(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    (new / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    assert any(f.rule_id == "SC003" for f in report.still_open)


def test_render_markdown_contains_sections(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "bad.sol").write_text(VULN_CONTRACT, encoding="utf-8")
    report = build_delta(old, new)
    md = render_markdown(report)
    assert isinstance(md, str)
    assert "Fix Review Delta Report" in md
    assert "## File changes" in md
    assert "## Findings delta" in md
    assert "### Fixed (" in md
    assert "### Still open (" in md
    assert "### New (" in md
