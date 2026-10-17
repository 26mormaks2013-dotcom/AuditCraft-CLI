"""Tests for auditcraft.core.sloc_counter."""

from __future__ import annotations

import json
from pathlib import Path

from auditcraft.core.sloc_counter import (
    DEFAULT_EXCLUDES,
    count_file,
    count_scope,
    count_text,
    report_to_json,
)

SOLIDITY_SAMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*
 * Block comment
 */
contract Foo {
    uint256 public x; // trailing comment

    function bar() external {}
}
"""


def test_count_text_basic_nsloc() -> None:
    scope = count_text(SOLIDITY_SAMPLE, language="solidity")
    # 11 lines: 4 comment lines (1 line + 3 block) + 2 blank => nSLOC = 5
    assert scope.total == 11
    assert scope.comments == 4
    assert scope.blank == 2
    assert scope.nsloc == 5


def test_count_text_strings_ignore_comments() -> None:
    text = 'string memory s = "// not a comment";\n'
    scope = count_text(text, language="solidity")
    assert scope.comments == 0
    assert scope.nsloc == 1


def test_count_file_reads_disk(tmp_path: Path) -> None:
    p = tmp_path / "Sample.sol"
    p.write_text(SOLIDITY_SAMPLE, encoding="utf-8")
    scope = count_file(p)
    assert scope.language == "solidity"
    assert scope.nsloc == 5
    assert scope.path == p


def test_count_scope_respects_default_excludes(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "b.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")

    report = count_scope(tmp_path)
    assert report.files == 1
    assert all("test" not in f.path.parts for f in report.per_file)
    assert set(DEFAULT_EXCLUDES).issuperset({"node_modules", "lib", "target", "out", "test", "mock"})


def test_count_scope_include_filter(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    (tmp_path / "b.rs").write_text("fn main() {}\n", encoding="utf-8")

    report = count_scope(tmp_path, include=[".rs"])
    assert report.files == 1
    assert report.per_file[0].language == "rust"


def test_report_to_json_is_valid_json(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    report = count_scope(tmp_path)
    payload = json.loads(report_to_json(report))
    assert payload["files"] == 1
    assert payload["nsloc"] == 1
    assert payload["per_file"][0]["language"] == "solidity"
