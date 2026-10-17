// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 06: Unprotected delegatecall — triggers SC004.
// The proxy delegates execution to an arbitrary implementation address
// supplied by the caller, with no access control and no allow-list.
// An attacker can point it at a malicious contract and take over storage.
contract VulnerableDelegate {
    address public owner;
    address public implementation;

    // No onlyOwner guard and arbitrary _impl — SC004.
    function setImplementation(address _impl) external {
        implementation = _impl;
    }

    // delegatecall to a caller-influenced target — SC004.
    function forward(address _target, bytes calldata _data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = _target.delegatecall(_data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
