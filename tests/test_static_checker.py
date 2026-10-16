"""Tests for auditcraft.core.static_checker."""

from __future__ import annotations

from pathlib import Path

from auditcraft.core.static_checker import RULES, list_rules, run_checks


FLOATING_PRAGMA = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Foo {}
"""

UNCHECKED_CALL = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Bar {
    function pay(address payable to) external {
        to.call{value: 1 ether}("");
    }
}
"""

SELFDESTRUCT_NO_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Baz {
    function kill() external { selfdestruct(payable(msg.sender)); }
}
"""

DELEGATECALL_NO_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Qux {
    function go(address target) external { target.delegatecall(""); }
}
"""

ZERO_ADDR_MISSING = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Z {
    function set(address who) external { }
}
"""

RUST_UNWRAP = """pub fn handler(ctx: Context<Init>) -> Result<()> {
    let x = some_result.unwrap();
    Ok(())
}
"""

RUST_ANCHOR_NO_OWNER = """pub fn initialize(ctx: Context<Init>) -> Result<()> {
    Ok(())
}
"""


def test_list_rules_returns_all_7() -> None:
    rules = list_rules()
    ids = {r.rule_id for r in rules}
    assert ids == {"SC001", "SC002", "SC003", "SC004", "SC005", "RS001", "RS002"}
    assert len(RULES) >= 7


def test_floating_pragma_detected(tmp_path: Path) -> None:
    p = tmp_path / "a.sol"
    p.write_text(FLOATING_PRAGMA, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "SC001" for f in result.findings)


def test_unchecked_call_detected(tmp_path: Path) -> None:
    p = tmp_path / "b.sol"
    p.write_text(UNCHECKED_CALL, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "SC002" for f in result.findings)


def test_selfdestruct_without_guard_detected(tmp_path: Path) -> None:
    p = tmp_path / "c.sol"
    p.write_text(SELFDESTRUCT_NO_GUARD, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "SC003" for f in result.findings)


def test_delegatecall_without_guard_detected(tmp_path: Path) -> None:
    p = tmp_path / "d.sol"
    p.write_text(DELEGATECALL_NO_GUARD, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "SC004" for f in result.findings)


def test_zero_address_check_missing_detected(tmp_path: Path) -> None:
    p = tmp_path / "e.sol"
    p.write_text(ZERO_ADDR_MISSING, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "SC005" for f in result.findings)


def test_rust_unwrap_detected(tmp_path: Path) -> None:
    p = tmp_path / "a.rs"
    p.write_text(RUST_UNWRAP, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "RS001" for f in result.findings)


def test_anchor_missing_owner_detected(tmp_path: Path) -> None:
    p = tmp_path / "b.rs"
    p.write_text(RUST_ANCHOR_NO_OWNER, encoding="utf-8")
    result = run_checks(tmp_path)
    assert any(f.rule_id == "RS002" for f in result.findings)


def test_rules_filter_and_min_severity(tmp_path: Path) -> None:
    (tmp_path / "mix.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract K { function f(address a) external {} }\n",
        encoding="utf-8",
    )
    only_sc001 = run_checks(tmp_path, rules=["SC001"])
    assert {f.rule_id for f in only_sc001.findings} == {"SC001"}

    criticals = run_checks(tmp_path, min_severity="critical")
    assert all(f.severity.value == "critical" for f in criticals.findings)
