// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20PresetMinterPauser} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";

import {PRBProxy} from "prb-proxy/PRBProxy.sol";

import "./IntegrationTestBase.sol";
import {wdiv, WAD} from "../../utils/Math.sol";
import {Permission} from "../../utils/Permission.sol";

import {CDPVault} from "../../CDPVault.sol";
import {StakingLPEth} from "../../StakingLPEth.sol";

import {PermitParams} from "../../proxy/TransferAction.sol";
import {SwapAction, SwapParams, SwapType, SwapProtocol} from "../../proxy/SwapAction.sol";
import {PoolActionParams, PoolActionParams, Protocol} from "../../proxy/PoolAction.sol";

import {PositionAction, CollateralParams, CreditParams, LeverParams} from "../../proxy/PositionAction.sol";

import {PositionAction4626} from "../../proxy/PositionAction4626.sol";

contract PositionAction4626_Lever_Test is IntegrationTestBase {
    using SafeERC20 for ERC20;

    PRBProxy userProxy;
    address user;
    CDPVault vault;
    StakingLPEth stakingLPEth;
    PositionAction4626 positionAction;
    PermitParams emptyPermitParams;
    SwapParams emptySwap;
    PoolActionParams emptyPoolActionParams;

    bytes32[] weightedPoolIdArray;

    address constant wstETH_bb_a_WETH_BPTl = 0x41503C9D499ddbd1dCdf818a1b05e9774203Bf46;
    address constant wstETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address constant bbaweth = 0xbB6881874825E60e1160416D6C426eae65f2459E;
    bytes32 constant poolId = 0x41503c9d499ddbd1dcdf818a1b05e9774203bf46000000000000000000000594;

    function setUp() public override {
        super.setUp();
        setGlobalDebtCeiling(15_000_000 ether);

        token = ERC20PresetMinterPauser(wstETH);

        stakingLPEth = new StakingLPEth(address(token), "Staking LP ETH", "sLPETH");
        stakingLPEth.setCooldownDuration(0);
        vault = createCDPVault(stakingLPEth, 5_000_000 ether, 0, 1.25 ether, 1.0 ether, 1.05 ether);
        createGaugeAndSetGauge(address(vault), address(stakingLPEth));

        user = vm.addr(0x12341234);
        userProxy = PRBProxy(payable(address(prbProxyRegistry.deployFor(user))));

        positionAction = new PositionAction4626(
            address(flashlender),
            address(swapAction),
            address(poolAction),
            address(vaultRegistry)
        );

        weightedUnderlierPoolId = _createBalancerPool(address(token), address(underlyingToken)).getPoolId();

        oracle.updateSpot(address(token), 1 ether);
        oracle.updateSpot(address(stakingLPEth), 1 ether);
        weightedPoolIdArray.push(weightedUnderlierPoolId);
    }

    function test_wrongTokenOutAmount_decreaseLeverLossOfFunds() public {
        uint256 depositAmount = 250 ether;
        uint256 borrowAmount = 100 ether;

        uint256 flashLoanAmount = borrowAmount / 2;

        deal(address(token), user, depositAmount);

        address[] memory assets = new address[](2);
        assets[0] = address(underlyingToken);
        assets[1] = address(token);

        address[] memory tokens = new address[](3);
        tokens[0] = wstETH_bb_a_WETH_BPTl;
        tokens[1] = wstETH;
        tokens[2] = bbaweth;

        vm.startPrank(user);

        // Deposit `wstETH` to get `sLPETH`
        // Deposit 250 `sLPETH` to vault
        {
            token.approve(address(stakingLPEth), depositAmount);
            stakingLPEth.approve(address(userProxy), depositAmount);

            stakingLPEth.deposit(depositAmount, user);

            userProxy.execute(
                address(positionAction),
                abi.encodeWithSelector(
                    positionAction.deposit.selector,
                    address(userProxy),
                    address(vault),
                    CollateralParams({
                        targetToken: address(stakingLPEth),
                        amount: depositAmount,
                        collateralizer: address(user),
                        auxSwap: emptySwap
                    }),
                    emptyPermitParams
                )
            );
        }

        // Borrow 100 ETH
        {
            userProxy.execute(
                address(positionAction),
                abi.encodeWithSelector(
                    positionAction.borrow.selector,
                    address(userProxy),
                    address(vault),
                    CreditParams({amount: borrowAmount, creditor: user, auxSwap: emptySwap})
                )
            );

            // Collateral is 250 ETH, debt is 100 ETH
            (uint256 collateral, uint256 debt, , , , ) = vault.positions(address(userProxy));
            assertEq(collateral, depositAmount);
            assertEq(debt, borrowAmount);
        }

        // Increase leverage
        // Takes a flash loan of 50 ETH borrow tokens (adds that as a debt)
        // Swap the borrow tokens to collateral tokens, and join Balancer pool
        // (around 49 collateral tokens are deposited into the balancer position)
        {
            uint256[] memory maxAmountsIn = new uint256[](3);
            maxAmountsIn[0] = 0;
            maxAmountsIn[1] = borrowAmount / 2 - 1 ether;
            maxAmountsIn[2] = 0;
            uint256[] memory tokensIn = new uint256[](2);
            tokensIn[0] = borrowAmount / 2 - 1 ether;
            tokensIn[1] = 0;

            userProxy.execute(
                address(positionAction),
                abi.encodeWithSelector(
                    positionAction.increaseLever.selector,
                    LeverParams({
                        position: address(userProxy),
                        vault: address(vault),
                        collateralToken: address(stakingLPEth),
                        primarySwap: SwapParams({
                            swapProtocol: SwapProtocol.BALANCER,
                            swapType: SwapType.EXACT_IN,
                            assetIn: address(underlyingToken),
                            amount: flashLoanAmount,
                            limit: 0,
                            recipient: address(positionAction),
                            residualRecipient: user,
                            deadline: block.timestamp,
                            args: abi.encode(weightedPoolIdArray, assets)
                        }),
                        auxSwap: emptySwap,
                        auxAction: PoolActionParams(
                            Protocol.BALANCER,
                            0,
                            user,
                            abi.encode(poolId, tokens, tokensIn, maxAmountsIn)
                        )
                    }),
                    address(0),
                    0,
                    address(user),
                    emptyPermitParams
                )
            );

            // Collateral remains the same, debt increases by 50 ETH
            // User has around 56 Balancer LP tokens
            (uint256 collateral, uint256 debt, , , , ) = vault.positions(address(userProxy));
            assertEq(collateral, depositAmount);
            uint256 flashloanFee = flashlender.flashFee(address(underlyingToken), flashLoanAmount);

            assertEq(debt, borrowAmount + flashLoanAmount + flashloanFee);
            assertEq(IERC20(wstETH_bb_a_WETH_BPTl).balanceOf(user) / 1 ether, 56);
        }

        {
            // Verify that the position action contract and the user don't hold any collateral tokens
            assertEq(token.balanceOf(address(positionAction)), 0);
            assertEq(token.balanceOf(user), 0);

            uint256[] memory minAmountsOut = new uint256[](3);
            minAmountsOut[0] = 0;
            minAmountsOut[1] = 0;
            minAmountsOut[2] = 0;

            // Send the Balancer LP tokens to the position action contract, to exit the Balancer pool
            uint256 bptAmount = IERC20(wstETH_bb_a_WETH_BPTl).balanceOf(user);
            IERC20(wstETH_bb_a_WETH_BPTl).transfer(address(positionAction), bptAmount);

            // Leverage down the position
            // Takes a flash loan of 40 ETH borrow tokens (decreases the debt), withdraws 70 ETH collateral tokens (residual should be sent to the user)
            // Swap collateral tokens to borrow tokens, to repay the flash loan
            // Exits the Balancer pool, and sends the residual collateral tokens to the user (this is where the loss of funds occurs)
            userProxy.execute(
                address(positionAction),
                abi.encodeWithSelector(
                    positionAction.decreaseLever.selector,
                    LeverParams({
                        position: address(userProxy),
                        vault: address(vault),
                        collateralToken: address(stakingLPEth),
                        auxSwap: emptySwap,
                        primarySwap: SwapParams({
                            swapProtocol: SwapProtocol.BALANCER,
                            swapType: SwapType.EXACT_OUT,
                            assetIn: address(token),
                            amount: 40 ether,
                            limit: 50 ether,
                            recipient: address(positionAction),
                            residualRecipient: user,
                            deadline: block.timestamp,
                            args: abi.encode(weightedPoolIdArray, assets)
                        }),
                        auxAction: PoolActionParams(
                            Protocol.BALANCER,
                            0,
                            user,
                            abi.encode(poolId, wstETH_bb_a_WETH_BPTl, bptAmount, 0, tokens, minAmountsOut)
                        )
                    }),
                    70 ether,
                    address(user)
                )
            );

            // Collateral is 180 ETH, debt is 110 ETH
            uint256 flashloanFee = flashlender.flashFee(address(underlyingToken), 40 ether);
            (uint256 collateral, uint256 debt, , , , ) = vault.positions(address(userProxy));
            assertEq(collateral, depositAmount - 70 ether);
            assertGe(debt, borrowAmount + flashLoanAmount - 40 ether + flashloanFee);

            // All balancer LP tokens are burnt
            assertEq(IERC20(wstETH_bb_a_WETH_BPTl).balanceOf(user), 0);
            assertEq(IERC20(wstETH_bb_a_WETH_BPTl).balanceOf(address(positionAction)), 0);

            uint256 expectedBalance = (59 ether + (70 ether - 50 ether)) / 1 ether;
            assertEq(token.balanceOf(user) / 1 ether, expectedBalance);

            // Position action should hold 0 collateral tokens
            assertEq(token.balanceOf(address(positionAction)), 0);
        }
    }

    function _createBalancerPool(address t1, address t2) internal returns (IComposableStablePool pool_) {
        uint256 amount = 5_000_000_000 ether;
        deal(t1, address(this), amount);
        deal(t2, address(this), amount);

        uint256[] memory maxAmountsIn = new uint256[](2);
        address[] memory assets = new address[](2);
        assets[0] = t1;
        uint256[] memory weights = new uint256[](2);
        weights[0] = 500000000000000000;
        weights[1] = 500000000000000000;

        bool tokenPlaced;
        address tempAsset;
        for (uint256 i; i < assets.length; i++) {
            if (!tokenPlaced) {
                if (uint160(assets[i]) > uint160(t2)) {
                    tokenPlaced = true;
                    tempAsset = assets[i];
                    assets[i] = t2;
                } else if (i == assets.length - 1) {
                    assets[i] = t2;
                }
            } else {
                address placeholder = assets[i];
                assets[i] = tempAsset;
                tempAsset = placeholder;
            }
        }

        for (uint256 i; i < assets.length; i++) {
            maxAmountsIn[i] = ERC20(assets[i]).balanceOf(address(this));
            ERC20(assets[i]).safeApprove(address(balancerVault), maxAmountsIn[i]);
        }

        pool_ = weightedPoolFactory.create(
            "50WETH-50TOKEN",
            "50WETH-50TOKEN",
            assets,
            weights,
            3e14, // swapFee (0.03%)
            address(this) // owner
        );

        balancerVault.joinPool(
            pool_.getPoolId(),
            address(this),
            address(this),
            JoinPoolRequest({
                assets: assets,
                maxAmountsIn: maxAmountsIn,
                userData: abi.encode(JoinKind.INIT, maxAmountsIn),
                fromInternalBalance: false
            })
        );
    }

    function getForkBlockNumber() internal pure virtual override(IntegrationTestBase) returns (uint256) {
        return 17870449; // Aug-08-2023 01:17:35 PM +UTC
    }
}