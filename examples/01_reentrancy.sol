// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 01: Reentrancy (CEI violation) — triggers SC006.
// The contract sends ETH via a low-level call BEFORE updating the balance,
// so a malicious receiver can re-enter withdraw() and drain the vault.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // External call BEFORE state update.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // State write after the external call (CEI violation) — SC006.
        balances[msg.sender] = 0;
    }
}
