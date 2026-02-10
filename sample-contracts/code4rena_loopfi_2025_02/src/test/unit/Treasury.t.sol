// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {TestBase, ERC20PresetMinterPauser} from "../TestBase.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Treasury, FUNDS_ADMINISTRATOR_ROLE} from "../../Treasury.sol";

contract TreasuryTest is TestBase {

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    
    address public fundAdmin = vm.addr(1);
    address[] public payees;
    uint256[] public shares;

    Treasury public treasury;

    function setUp() public override {
        super.setUp();

        payees = new address[](2);
        shares = new uint256[](2);

        payees[0] = vm.addr(2);
        payees[1] = vm.addr(3);
        shares[0] = 10;
        shares[1] = 10;

        treasury = new Treasury(payees, shares, fundAdmin);
    }

    function test_deploy() public {
        assertNotEq(address(treasury), address(0));
        assertTrue(treasury.hasRole(FUNDS_ADMINISTRATOR_ROLE, fundAdmin));
        assertTrue(treasury.hasRole(DEFAULT_ADMIN_ROLE, address(this)));

        assertEq(treasury.payee(0), payees[0]);
        assertEq(treasury.payee(1), payees[1]);
        assertEq(treasury.shares(payees[0]), shares[0]);
        assertEq(treasury.shares(payees[1]), shares[1]);
    }

    function test_release_scenario() public {
        uint256 amount = 1000 ether;
        mockWETH.mint(address(treasury), amount);
        treasury.release(IERC20(address(mockWETH)), payees[0]);

        uint256 expectedAmount = amount * 50 / 100; // 50% shares
        assertEq(treasury.released(IERC20(address(mockWETH)), payees[0]), expectedAmount);
        assertEq(treasury.releasable(IERC20(address(mockWETH)), payees[0]), 0);
        assertEq(treasury.releasable(IERC20(address(mockWETH)), payees[1]), expectedAmount);

        assertEq(treasury.totalReleased(), 0);
        assertEq(treasury.totalReleased(IERC20(address(mockWETH))), expectedAmount);

        assertEq(mockWETH.balanceOf(address(treasury)), amount - expectedAmount);
        assertEq(mockWETH.balanceOf(payees[0]), expectedAmount);
        assertEq(mockWETH.balanceOf(payees[1]), 0);
    }

    function test_moveFunds_eth() public {
        uint256 amount = 1000 ether;
        deal(address(treasury), amount);

        address payable newTreasury = payable(vm.addr(4));
        vm.prank(fundAdmin);
        treasury.moveFunds(newTreasury);

        assertEq(address(newTreasury).balance, amount);
        assertEq(address(treasury).balance, 0);
    }

    function test_moveFunds_eth_revertIfNotAdmin() public {
        uint256 amount = 1000 ether;
        deal(address(treasury), amount);

        address payable newTreasury = payable(vm.addr(4));
        vm.expectRevert("AccessControl: account 0xc15d2ba57d126e6603240e89437efd419ce329d2 is missing role 0x1de81697deb5d12103080160b4edf052df2632ec503c599f09935757d5383cf9");
        treasury.moveFunds(newTreasury);
    }

    function test_moveFunds_erc20() public {
        uint256 amount = 1000 ether;
        mockWETH.mint(address(treasury), amount);

        address newTreasury = vm.addr(4);
        vm.prank(fundAdmin);
        treasury.moveFunds(newTreasury, IERC20(address(mockWETH)));

        assertEq(mockWETH.balanceOf(newTreasury), amount);
        assertEq(mockWETH.balanceOf(address(treasury)), 0);
    }

    function test_moveFunds_erc20_revertIfNotAdmin() public {
        uint256 amount = 1000 ether;
        mockWETH.mint(address(treasury), amount);

        address newTreasury = vm.addr(4);
        vm.expectRevert("AccessControl: account 0xc15d2ba57d126e6603240e89437efd419ce329d2 is missing role 0x1de81697deb5d12103080160b4edf052df2632ec503c599f09935757d5383cf9");
        treasury.moveFunds(newTreasury, IERC20(address(mockWETH)));
    }

    function test_moveFunds_multipleTokens() public {
        uint256 amount = 1000 ether;
        mockWETH.mint(address(treasury), amount);
        token.mint(address(treasury), amount);

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(address(mockWETH));
        tokens[1] = IERC20(address(token));

        address newTreasury = vm.addr(4);
        vm.prank(fundAdmin);
        treasury.moveFunds(newTreasury, tokens);

        for (uint256 i=0; i<tokens.length; i++) {
            assertEq(tokens[i].balanceOf(newTreasury), amount);
            assertEq(tokens[i].balanceOf(address(treasury)), 0);
        }
    }

    function test_moveFunds_multipleTokens_revertIfNotAdmin() public {
        uint256 amount = 1000 ether;
        mockWETH.mint(address(treasury), amount);
        token.mint(address(treasury), amount);

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(address(mockWETH));
        tokens[1] = IERC20(address(token));

        address newTreasury = vm.addr(4);
        vm.expectRevert("AccessControl: account 0xc15d2ba57d126e6603240e89437efd419ce329d2 is missing role 0x1de81697deb5d12103080160b4edf052df2632ec503c599f09935757d5383cf9");
        treasury.moveFunds(newTreasury, tokens);
    }
}
