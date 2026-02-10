// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "pendle/interfaces/IRewardManager.sol";

import "pendle/core/libraries/ArrayLib.sol";
import "pendle/core/libraries/TokenHelper.sol";
import "pendle/core/libraries/math/PMath.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "./RewardManagerAbstract.sol";
import {console} from "forge-std/console.sol";

/// NOTE: RewardManager must not have duplicated rewardTokens
abstract contract RewardManagerAbstract is IRewardManager, TokenHelper {
    using PMath for uint256;
    using SafeCast for int256;

    uint256 internal constant INITIAL_REWARD_INDEX = 1;

    struct RewardState {
        uint128 index;
        uint128 lastBalance;
    }

    struct UserReward {
        uint128 index;
        uint128 accrued;
    }
    uint256 internal _totalShares;
    // [token] => [user] => (index,accrued)
    mapping(address => mapping(address => UserReward)) public userReward;

    function _updateAndDistributeRewards(
        address user,
        uint256 collateralAmountBefore,
        int256 deltaCollateral
    ) internal virtual {
        _updateAndDistributeRewardsForTwo(user, collateralAmountBefore);
        if (deltaCollateral > 0) _totalShares = _totalShares + deltaCollateral.toUint256();
        else _totalShares = _totalShares - (-deltaCollateral).toUint256();
    }

    function _updateAndDistributeRewardsForTwo(address user1, uint256 collateralAmountBefore) internal virtual {
        (address[] memory tokens, uint256[] memory indexes) = _updateRewardIndex();
        if (tokens.length == 0) return;

        if (user1 != address(0) && user1 != address(this))
            _distributeRewardsPrivate(user1, collateralAmountBefore, tokens, indexes);
    }

    // should only be callable from `_updateAndDistributeRewardsForTwo` to guarantee user != address(0) && user != address(this)
    function _distributeRewardsPrivate(
        address user,
        uint256 collateralAmountBefore,
        address[] memory tokens,
        uint256[] memory indexes
    ) private {
        assert(user != address(0) && user != address(this));

        //  uint256 userShares = _rewardSharesUser(user);
        uint256 userShares = collateralAmountBefore;
        for (uint256 i = 0; i < tokens.length; ++i) {
            address token = tokens[i];
            uint256 index = indexes[i];
            uint256 userIndex = userReward[token][user].index;

            if (userIndex == 0) {
                userIndex = INITIAL_REWARD_INDEX.Uint128();
            }

            if (userIndex == index) continue;

            uint256 deltaIndex = index - userIndex;

            uint256 rewardDelta = userShares.mulDown(deltaIndex);
            uint256 rewardAccrued = userReward[token][user].accrued + rewardDelta;
            userReward[token][user] = UserReward({index: index.Uint128(), accrued: rewardAccrued.Uint128()});
        }
    }

    function _updateRewardIndex() internal virtual returns (address[] memory tokens, uint256[] memory indexes);

    function _doTransferOutRewards(
        address user
    ) internal virtual returns (address[] memory tokens, uint256[] memory rewardAmounts, address to);
}
