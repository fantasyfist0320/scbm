// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title Locking contract
/// @notice A contract that allows users to deposit tokens and withdraw them after a cooldown period
contract Locking is Ownable {
    using SafeERC20 for IERC20;

    error AmountIsZero();
    error InsufficientBalanceForCooldown();
    error NoTokensInCooldown();
    error CooldownPeriodNotPassed();

    uint256 public cooldownPeriod;
    IERC20 public token;

    struct Deposit {
        uint256 amount;
        uint256 cooldownStart;
        uint256 cooldownAmount;
    }

    mapping(address => Deposit) public deposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event CooldownPeriodSet(uint256 cooldownPeriod);
    event CooldownInitiated(address indexed user, uint256 timestamp, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Set the cooldown period for withdrawing tokens
    /// @param _cooldownPeriod The new cooldown period in seconds
    function setCooldownPeriod(uint256 _cooldownPeriod) external onlyOwner {
        cooldownPeriod = _cooldownPeriod;
        emit CooldownPeriodSet(_cooldownPeriod);
    }

    /// @notice Deposit tokens into the contract
    /// @param _amount The amount of tokens to deposit
    function deposit(uint256 _amount) external {
        if (_amount == 0) revert AmountIsZero();

        deposits[msg.sender].amount += _amount;
        token.safeTransferFrom(msg.sender, address(this), _amount);

        emit Deposited(msg.sender, _amount);
    }

    /// @notice Initiate a cooldown period for withdrawing tokens
    /// @dev If the user initiates again before the cooldown period has passed or before withdrawing the already available tokens, the cooldown amount and start time will be updated
    /// @param _amount The amount of tokens to set the cooldown for
    function initiateCooldown(uint256 _amount) external {
        if (_amount == 0) revert AmountIsZero();
        if (deposits[msg.sender].amount < _amount) revert InsufficientBalanceForCooldown();
        deposits[msg.sender].cooldownStart = block.timestamp;
        deposits[msg.sender].cooldownAmount = _amount;

        emit CooldownInitiated(msg.sender, block.timestamp, _amount);
    }

    /// @notice Withdraw tokens from the contract
    /// @dev If there's a cooldown period set, the tokens can be withdrawn after the cooldown period has passed
    function withdraw() external {
        uint256 _amount;
        if (cooldownPeriod > 0) {
            if (deposits[msg.sender].cooldownAmount == 0) revert NoTokensInCooldown();
            if (block.timestamp < deposits[msg.sender].cooldownStart + cooldownPeriod) revert CooldownPeriodNotPassed();
            _amount = deposits[msg.sender].cooldownAmount;
        } else {
            _amount = deposits[msg.sender].amount;
        }

        deposits[msg.sender].amount -= _amount;
        deposits[msg.sender].cooldownAmount = 0;
        deposits[msg.sender].cooldownStart = 0;
        token.safeTransfer(msg.sender, _amount);

        emit Withdrawn(msg.sender, _amount);
    }

    /// @notice Get the balance of a user
    /// @param _user The address of the user
    /// @return The balance of the user
    function getBalance(address _user) external view returns (uint256) {
        return deposits[_user].amount;
    }

    /// @notice Get the cooldown info of a user
    /// @param _user The address of the user
    /// @return The deposit amount, start time, and cooldown amount of the user
    function getCoolDownInfo(address _user) external view returns (uint256, uint256, uint256) {
        return (deposits[_user].amount, deposits[_user].cooldownStart, deposits[_user].cooldownAmount);
    }
}
