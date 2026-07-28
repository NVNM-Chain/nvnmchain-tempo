// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { GuardedSwapper } from "../src/GuardedSwapper.sol";
import { MockERC20 } from "./support/MockERC20.sol";
import { MockSwapPool } from "./support/MockSwapPool.sol";
import { Test } from "forge-std/Test.sol";

contract GuardedSwapperTest is Test {
    GuardedSwapper guard;
    MockSwapPool pool;
    MockERC20 usd;
    MockERC20 nvnm;

    address owner = makeAddr("safe");
    address keeper = makeAddr("keeper");

    function setUp() public {
        usd = new MockERC20("nvmnUSD", "nvmnUSD");
        nvnm = new MockERC20("NVNM", "NVNM");
        pool = new MockSwapPool(address(usd), address(nvnm));
        usd.mint(address(pool), 1000 ether);
        nvnm.mint(address(pool), 1000 ether); // spot price 1:1

        guard = new GuardedSwapper(owner, address(usd), address(nvnm));
        vm.startPrank(owner);
        guard.setGuards(address(pool), 50 ether, 500, 2000); // cap 50, -5% floor, alpha 20%
        guard.seedPrice(1 ether); // 1 NVNM per USD
        vm.stopPrank();

        usd.mint(keeper, 1000 ether);
        vm.prank(keeper);
        usd.approve(address(guard), type(uint256).max);
    }

    function _swap(uint256 amountIn) internal returns (uint256) {
        vm.prank(keeper);
        return guard.swap(address(usd), address(nvnm), amountIn, 0);
    }

    function test_swap_withinGuards() public {
        uint256 out = _swap(10 ether); // x*y=k: 1000*10/1010 ≈ 9.9 -> ~1% impact, within 5%
        assertEq(nvnm.balanceOf(keeper), out);
        assertGt(out, 9.8 ether);
        assertLt(guard.emaPrice(), 1 ether); // EMA followed the (slightly lower) execution price
    }

    function test_swap_sizeCapEnforced() public {
        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.AmountTooLarge.selector);
        guard.swap(address(usd), address(nvnm), 51 ether, 0);
    }

    function test_swap_manipulatedPoolReverts() public {
        // Sandwich front-run: drain most of the NVNM side so execution price collapses.
        vm.prank(address(pool));
        nvnm.transfer(address(0xdead), 900 ether);

        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.PriceBelowFloor.selector);
        guard.swap(address(usd), address(nvnm), 10 ether, 0);
    }

    function test_swap_requiresSeedAndInner() public {
        GuardedSwapper fresh = new GuardedSwapper(owner, address(usd), address(nvnm));
        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.NotSeeded.selector);
        fresh.swap(address(usd), address(nvnm), 1 ether, 0);
    }

    function test_swap_wrongPairReverts() public {
        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.WrongPair.selector);
        guard.swap(address(nvnm), address(usd), 1 ether, 0);
    }

    function test_setGuards_rejectsBpsOverOneHundredPercent() public {
        vm.startPrank(owner);
        vm.expectRevert(GuardedSwapper.InvalidBps.selector);
        guard.setGuards(address(pool), 50 ether, 10_001, 2000);
        vm.expectRevert(GuardedSwapper.InvalidBps.selector);
        guard.setGuards(address(pool), 50 ether, 500, 10_001);
        vm.stopPrank();
    }

    function test_swap_zeroAmountReverts() public {
        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.ZeroAmount.selector);
        guard.swap(address(usd), address(nvnm), 0, 0);
    }

    function test_onlyOwnerConfigures() public {
        vm.startPrank(keeper);
        vm.expectRevert();
        guard.setGuards(address(pool), 1, 1, 1);
        vm.expectRevert();
        guard.seedPrice(2 ether);
        vm.stopPrank();
    }

    function test_ema_admitsDriftButLimitsCumulativeDrain() public {
        // Small swaps drift the EMA down and keep passing...
        _swap(10 ether);
        _swap(10 ether);
        assertLt(guard.emaPrice(), 1 ether);

        // ...but a large drain (price ~-7% vs the lagging EMA) is rejected...
        vm.prank(keeper);
        vm.expectRevert(GuardedSwapper.PriceBelowFloor.selector);
        guard.swap(address(usd), address(nvnm), 40 ether, 0);

        // ...while normal-sized swaps continue to clear.
        assertGt(_swap(5 ether), 0);
    }
}
