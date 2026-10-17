// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Example 03: Unchecked ERC20 transfer — triggers SC008.
// Using the raw ERC20 transfer() instead of SafeERC20.safeTransfer() can
// silently fail for non-standard tokens that return false or nothing.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerablePayout {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // Direct ERC20 transfer() — SC008.
    function payout(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    // Direct transferFrom() — SC008.
    function pull(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
    }
}
