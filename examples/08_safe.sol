// SPDX-License-Identifier: MIT

// Example 08: Safe contract — should trigger NO rules.
// Demonstrates best practices:
//   * locked pragma version
//   * checks-effects-interactions ordering + nonReentrant
//   * SafeERC20 for token transfers
//   * access control with a timelock for privileged ops
//   * no unprotected selfdestruct / delegatecall
pragma solidity 0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(to != address(0), "zero address");
        require(token.transfer(to, amount), "safeTransfer failed");
    }
}

contract SafeVault {
    using SafeERC20 for IERC20;

    address public owner;
    bool private locked;
    mapping(address => uint256) public balances;

    uint256 public constant TIMELOCK = 2 days;
    uint256 public pendingFee;
    uint256 public feeEffectiveAt;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // CEI ordering + nonReentrant: state updated before external call.
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // SafeERC20 wrapper instead of raw transfer.
    function payout(IERC20 token, address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    // Timelocked privileged operation.
    function scheduleFee(uint256 _fee) external onlyOwner {
        pendingFee = _fee;
        feeEffectiveAt = block.timestamp + TIMELOCK;
    }

    function applyFee() external {
        require(block.timestamp >= feeEffectiveAt, "timelock active");
        // apply pendingFee...
    }
}
