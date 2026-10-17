// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 04: Centralization risk — triggers SC009.
// Privileged functions guarded only by onlyOwner perform critical operations
// (withdraw / pause / upgrade) without any timelock or delay, so the owner
// can rug-pull users instantly.
contract CentralizedVault {
    address public owner;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // onlyOwner + withdraw without any timelock — SC009.
    function withdraw() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }

    // onlyOwner + pause without timelock — SC009.
    function pause() external onlyOwner {
        paused = true;
    }

    // onlyOwner + setFee without timelock — SC009.
    function setFee(uint256) external onlyOwner {
        // fee update
    }
}
