// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {ERC20PresetMinterPauser} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";
import {PRBProxy} from "prb-proxy/PRBProxy.sol";
import {WAD} from "../../utils/Math.sol";
import {IntegrationTestBase} from "./IntegrationTestBase.sol";
import {PoolV3} from "../../PoolV3.sol";
import {LinearInterestRateModelV3} from "@gearbox-protocol/core-v3/contracts/pool/LinearInterestRateModelV3.sol";

contract PoolV3Test is IntegrationTestBase {
    using SafeERC20 for ERC20;

    PoolV3 wethPool;
    function setUp() public override {
      super.setUp();

      LinearInterestRateModelV3 irm = new LinearInterestRateModelV3({
          U_1: 85_00,
          U_2: 95_00,
          R_base: 10_00,
          R_slope1: 20_00,
          R_slope2: 30_00,
          R_slope3: 40_00,
          _isBorrowingMoreU2Forbidden: false
      });

      wethPool = new PoolV3({
          weth_: address(WETH),
          addressProvider_: address(addressProvider),
          underlyingToken_: address(WETH),
          interestRateModel_: address(irm),
          totalDebtLimit_: initialGlobalDebtCeiling,
          name_: "Loop Liquidity Pool",
          symbol_: "lpETH "
      });
    }


    function test_deploy() public {
        assertNotEq(address(wethPool), address(0));
    }

    function test_depositEth() public {
      uint256 balanceBefore = address(this).balance;
      uint256 poolBalanceBefore = WETH.balanceOf(address(wethPool));
      uint256 shares = wethPool.depositETH{value: 1 ether}(address(this));
      
      uint256 balanceAfter = address(this).balance;
      uint256 poolBalanceAfter = WETH.balanceOf(address(wethPool));

      assertEq(shares, 1 ether);
      assertEq(balanceBefore - balanceAfter, 1 ether);
      assertEq(poolBalanceAfter - poolBalanceBefore, 1 ether);
    }

    function test_depositEth_revertsIfNotEnoughEth() public {
      address depositor = address(0x123);

      deal(depositor, 0);
      vm.prank(depositor);
      vm.expectRevert();
      wethPool.depositETH{value: 1 ether}(address(this));

      deal(depositor, 1 ether);
      vm.prank(depositor);
      uint256 shares = wethPool.depositETH{value: 1 ether}(address(this));
      assertEq(shares, 1 ether);
    }

    function test_depositEth_revertsIfNoEthSent() public {
      vm.expectRevert(PoolV3.NoEthSent.selector);
      wethPool.depositETH{value: 0}(address(this));
    }

    function test_depositEth_revertsIfNotWeth() public {
      // the liquidity pool is initialized with a custom token as the underlying token
      vm.expectRevert(PoolV3.WrongUnderlying.selector);
      liquidityPool.depositETH{value: 1 ether}(address(this));
    }
}
