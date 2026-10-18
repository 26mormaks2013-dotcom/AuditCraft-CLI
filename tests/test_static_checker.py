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


def test_list_rules_returns_all_18() -> None:
    rules = list_rules()
    ids = {r.rule_id for r in rules}
    assert ids == {
        "SC001", "SC002", "SC003", "SC004", "SC005",
        "SC006", "SC007", "SC008", "SC009",
        "SC012", "SC013",
        "RS001", "RS002", "RS003", "RS004",
        "RS005", "RS006", "RS007",
    }
    assert len(RULES) >= 18


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


REENTRANCY = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract R {
    mapping(address => uint256) public bal;
    function w() external {
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
"""


INITIALIZER_NO_GUARD = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    function initialize(address o) external { }
}
"""


RAW_ERC20_TRANSFER = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract T {
    function send(IERC20 t, address to) external {
        t.transfer(to, 1);
    }
}
"""


CENTRALIZATION_RISK = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract C {
    function withdraw() external onlyOwner { }
}
"""


ANCHOR_NO_CONSTRAINT = """#[derive(Accounts)]
pub struct Init<'info> {
    pub authority: AccountInfo<'info>,
}
"""


ACCOUNTINFO_INSTEAD_OF_SIGNER = """#[derive(Accounts)]
pub struct Pay<'info> {
    pub payer: AccountInfo<'info>,
}
"""


def test_sc006_reentrancy(tmp_path: Path) -> None:
    (tmp_path / "r.sol").write_text(REENTRANCY, encoding="utf-8")
    assert any(f.rule_id == "SC006" for f in run_checks(tmp_path).findings)


def test_sc007_unprotected_initializer(tmp_path: Path) -> None:
    (tmp_path / "p.sol").write_text(INITIALIZER_NO_GUARD, encoding="utf-8")
    assert any(f.rule_id == "SC007" for f in run_checks(tmp_path).findings)


def test_sc008_raw_erc20_transfer(tmp_path: Path) -> None:
    (tmp_path / "t.sol").write_text(RAW_ERC20_TRANSFER, encoding="utf-8")
    assert any(f.rule_id == "SC008" for f in run_checks(tmp_path).findings)


def test_sc009_centralization(tmp_path: Path) -> None:
    (tmp_path / "c.sol").write_text(CENTRALIZATION_RISK, encoding="utf-8")
    assert any(f.rule_id == "SC009" for f in run_checks(tmp_path).findings)


def test_rs003_anchor_no_constraint(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(ANCHOR_NO_CONSTRAINT, encoding="utf-8")
    assert any(f.rule_id == "RS003" for f in run_checks(tmp_path).findings)


def test_rs004_missing_signer(tmp_path: Path) -> None:
    (tmp_path / "b.rs").write_text(ACCOUNTINFO_INSTEAD_OF_SIGNER, encoding="utf-8")
    assert any(f.rule_id == "RS004" for f in run_checks(tmp_path).findings)


# --- v0.4.0: Storage Collision, Cross-Function Reentrancy, Anchor Reinit/Duplicate/PDA ---

STORAGE_COLLISION = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract UnsafeProxy {
    address public implementation;
    uint256 public value;
    function upgrade(address target) external {
        (bool ok, ) = target.delegatecall("");
        require(ok);
    }
}
"""

CROSS_FUNCTION_REENTRANCY = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Bank {
    mapping(address => uint256) public balances;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

SAFE_PROXY_WITH_GAP = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract SafeProxy {
    address public implementation;
    uint256[49] private __gap;
    function upgrade(address target) external {
        (bool ok, ) = target.delegatecall("");
        require(ok);
    }
}
"""

ANCHOR_REINIT = """use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init_if_needed)]
    pub vault: Account<'info, VaultState>,
}
"""

ANCHOR_DUPLICATE_ACCOUNT = """use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct Pull<'info> {
    #[account(mut)]
    pub source: Account<'info, VaultState>,
    #[account(mut)]
    pub destination: Account<'info, VaultState>,
}
"""

ANCHOR_PDA_SHARING = """use anchor_lang::prelude::*;
#[derive(Accounts)]
pub struct Vault<'info> {
    #[account(seeds = ["vault"], bump)]
    pub vault_pda: Account<'info, VaultState>,
}
"""


def test_sc012_storage_collision(tmp_path: Path) -> None:
    (tmp_path / "p.sol").write_text(STORAGE_COLLISION, encoding="utf-8")
    assert any(f.rule_id == "SC012" for f in run_checks(tmp_path).findings)


def test_sc012_not_triggered_with_gap(tmp_path: Path) -> None:
    (tmp_path / "p.sol").write_text(SAFE_PROXY_WITH_GAP, encoding="utf-8")
    assert not any(f.rule_id == "SC012" for f in run_checks(tmp_path).findings)


def test_sc013_cross_function_reentrancy(tmp_path: Path) -> None:
    (tmp_path / "b.sol").write_text(CROSS_FUNCTION_REENTRANCY, encoding="utf-8")
    assert any(f.rule_id == "SC013" for f in run_checks(tmp_path).findings)


def test_rs005_account_reinit(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(ANCHOR_REINIT, encoding="utf-8")
    assert any(f.rule_id == "RS005" for f in run_checks(tmp_path).findings)


def test_rs006_duplicate_account(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(ANCHOR_DUPLICATE_ACCOUNT, encoding="utf-8")
    assert any(f.rule_id == "RS006" for f in run_checks(tmp_path).findings)


def test_rs007_pda_sharing(tmp_path: Path) -> None:
    (tmp_path / "a.rs").write_text(ANCHOR_PDA_SHARING, encoding="utf-8")
    assert any(f.rule_id == "RS007" for f in run_checks(tmp_path).findings)
