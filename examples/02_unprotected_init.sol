// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 02: Unprotected initializer — triggers SC007.
// The initialize() function can be called by anyone at any time,
// allowing an attacker to seize ownership of the proxy implementation.
contract VulnerableProxy {
    address public owner;
    uint256 public fee;

    // No `initializer` / `onlyInitializing` modifier — SC007.
    function initialize(address _owner, uint256 _fee) external {
        owner = _owner;
        fee = _fee;
    }

    function setFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        fee = _fee;
    }
}
