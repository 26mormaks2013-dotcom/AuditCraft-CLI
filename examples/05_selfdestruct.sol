// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 05: Unprotected selfdestruct — triggers SC003.
// Anyone can call destroy() to force-destroy the contract and sweep its
// balance, because there is no access-control guard on the function.
contract SelfDestructingVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // No onlyOwner / require(msg.sender) guard — SC003.
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
