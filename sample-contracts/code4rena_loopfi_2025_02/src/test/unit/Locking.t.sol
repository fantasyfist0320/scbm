// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/Locking.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MTK") {
        _mint(msg.sender, 1000000 ether);
    }
}

contract LockingTest is Test {
    Locking public depositContract;
    MockERC20 public token;
    address public owner;
    address public user;

    function setUp() public {
        owner = address(this);
        user = address(0x123);
        token = new MockERC20();
        depositContract = new Locking(address(token));
        depositContract.setCooldownPeriod(1 days);
        // Transfer some tokens to the user
        token.transfer(user, 1000 ether);
    }

    function testDeposit() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        vm.stopPrank();

        assertEq(depositContract.getBalance(user), 500 ether);
    }

    function testInitiateCooldown() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);
        vm.stopPrank();

        (uint256 amount, uint256 cooldownStart, uint256 cooldownAmount) = depositContract.deposits(user);
        assertEq(amount, 500 ether);
        assertEq(cooldownAmount, 500 ether);
        assertTrue(cooldownStart > 0);
    }

    function testWithdraw() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);

        // Fast forward time to pass the cooldown period
        vm.warp(block.timestamp + 1 days);

        depositContract.withdraw();
        vm.stopPrank();

        assertEq(depositContract.getBalance(user), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }

    function testWithdrawBeforeCooldown() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);

        // Attempt to withdraw before the cooldown period has passed
        vm.expectRevert(Locking.CooldownPeriodNotPassed.selector);
        depositContract.withdraw();
        vm.stopPrank();
    }

    function testSetCooldownPeriod() public {
        vm.startPrank(owner);
        depositContract.setCooldownPeriod(2 days);
        vm.stopPrank();

        assertEq(depositContract.cooldownPeriod(), 2 days);
    }

    function testSetCooldownPeriodNotOwner() public {
        vm.startPrank(user);
        vm.expectRevert("Ownable: caller is not the owner");
        depositContract.setCooldownPeriod(2 days);
        vm.stopPrank();
    }

    function testInitiateCooldownInsufficientBalance() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);

        vm.expectRevert(Locking.InsufficientBalanceForCooldown.selector);
        depositContract.initiateCooldown(600 ether);
        vm.stopPrank();

        vm.expectRevert(Locking.AmountIsZero.selector);
        depositContract.initiateCooldown(0);
        vm.stopPrank();
    }

    function testDepositZero() public {
        vm.startPrank(user);
        vm.expectRevert(Locking.AmountIsZero.selector);
        depositContract.deposit(0);
        vm.stopPrank();
    }

    function testCooldownCalledTwice() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 1000 ether);
        depositContract.deposit(1000 ether);
        depositContract.initiateCooldown(500 ether);
        depositContract.initiateCooldown(500 ether);

        // Fast forward time to pass the cooldown period
        vm.warp(block.timestamp + 1 days);

        depositContract.withdraw();
        vm.stopPrank();

        assertEq(depositContract.getBalance(user), 500 ether);
        assertEq(token.balanceOf(user), 500 ether);
    }

    function testCooldownReset() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 1000 ether);
        depositContract.deposit(1000 ether);
        depositContract.initiateCooldown(500 ether);

        // Fast forward time to pass the cooldown period
        vm.warp(block.timestamp + 12 hours);

        depositContract.initiateCooldown(500 ether);
        vm.stopPrank();

        (uint256 amount, uint256 cooldownStart, uint256 cooldownAmount) = depositContract.deposits(user);
        assertEq(amount, 1000 ether, "Amount should be 1000");
        assertEq(cooldownAmount, 500 ether, "Cooldown amount should be 500");
        assertTrue(cooldownStart > 0, "Cooldown start should be set");
    }

    // test that if a cooldown is set and a user starts the cooldown, if cooldown is set to zero he can immediately withdraw
    function testWithdrawZeroCooldown() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);
        vm.stopPrank();
        // Set cooldown period to zero
        depositContract.setCooldownPeriod(0);

        vm.prank(user);
        depositContract.withdraw();

        assertEq(depositContract.getBalance(user), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }

    // add test to check that if a user tries to withdraw with coolDownPeriod == 0, it will succeed
    function testWithdrawZeroCooldownPeriod() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);
        vm.stopPrank();
        // Set cooldown period to zero
        depositContract.setCooldownPeriod(0);

        vm.prank(user);
        depositContract.withdraw();

        assertEq(depositContract.getBalance(user), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }

    // add test to allow user withdraw if he has a cooldown but then the cooldown period is set to zero
    function testWithdrawZeroCooldownPeriodAfterCooldown() public {
        vm.startPrank(user);
        token.approve(address(depositContract), 500 ether);
        depositContract.deposit(500 ether);
        depositContract.initiateCooldown(500 ether);
        vm.stopPrank();

        // Set cooldown period to zero
        depositContract.setCooldownPeriod(0);

        vm.prank(user);
        depositContract.withdraw();

        assertEq(depositContract.getBalance(user), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }
}
