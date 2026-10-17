// SPDX-License-Identifier: MIT

// Example 07: Floating pragma — triggers SC001.
// A caret/floating pragma lets the contract compile with any future
// 0.8.x compiler, which may include breaking changes or new bugs.
// Fix: lock the version, e.g. `pragma solidity 0.8.20;`
pragma solidity ^0.8.0;

contract FloatingPragma {
    uint256 public value;

    function set(uint256 _value) external {
        value = _value;
    }
}
