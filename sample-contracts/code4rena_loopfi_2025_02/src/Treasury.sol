// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {PaymentSplitter} from "@openzeppelin/contracts/finance/PaymentSplitter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

bytes32 constant FUNDS_ADMINISTRATOR_ROLE = keccak256("FUNDS_ADMINISTRATOR_ROLE");

contract Treasury is AccessControl, PaymentSplitter {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SafeERC20 for IERC20;
    using SafeCast for int256;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Treasury__moveFunds(address treasury);

    constructor(address[] memory payees, uint256[] memory shares_, address fundsAdmin) PaymentSplitter(payees, shares_) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(FUNDS_ADMINISTRATOR_ROLE, fundsAdmin);
    }

    /// @notice Moves all the funds of the contract to a new treasury
    /// @param treasury The address of the new treasury
    /// @dev This function is only callable by the funds administrator
    function moveFunds(address payable treasury) external onlyRole(FUNDS_ADMINISTRATOR_ROLE) {
        uint256 payment = address(this).balance;
        Address.sendValue(treasury, payment);

        emit Treasury__moveFunds(treasury);
    }

    /// @notice Moves all the funds of the contract to a new treasury
    /// @param treasury The address of the new treasury
    /// @param token The token to move
    /// @dev This function is only callable by the funds administrator
    function moveFunds(address treasury, IERC20 token) external onlyRole(FUNDS_ADMINISTRATOR_ROLE) {
        _moveFunds(treasury, token);

        emit Treasury__moveFunds(treasury);
    }

    /// @notice Moves all the funds of the contract to a new treasury
    /// @param treasury The address of the new treasury
    /// @param tokens The tokens to move
    /// @dev This function is only callable by the funds administrator
    function moveFunds(address treasury, IERC20[] calldata tokens) external onlyRole(FUNDS_ADMINISTRATOR_ROLE) {
        uint256 len = tokens.length;
        for (uint256 i = 0; i < len; i++) {
            _moveFunds(treasury, tokens[i]);
        }

        emit Treasury__moveFunds(treasury);
    }

    /// @notice Moves all the funds of the contract to a new treasury
    /// @param treasury The address of the new treasury
    /// @param token The token to move
    /// @dev This function is only callable by the funds administrator
    function _moveFunds(address treasury, IERC20 token) internal {
        uint256 amount = token.balanceOf(address(this));
        if (amount > 0) {
            SafeERC20.safeTransfer(token, treasury, amount);
        }
    }
}
