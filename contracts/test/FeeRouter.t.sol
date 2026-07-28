// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { FeeRouter, FeeRouterFactory } from "../src/FeeRouter.sol";
import { NVNMStaking } from "../src/NVNMStaking.sol";
import { MockERC20 } from "./support/MockERC20.sol";
import { MockSwapPool } from "./support/MockSwapPool.sol";
import { Test } from "forge-std/Test.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { LibClone } from "solady/utils/LibClone.sol";

contract FeeRouterTest is Test {
    NVNMStaking staking;
    FeeRouterFactory factory;
    FeeRouter router;
    MockERC20 nvnm;
    MockERC20 usd;

    address owner = makeAddr("safe");
    address validator = makeAddr("validator");
    address operator = makeAddr("operator");
    address alice = makeAddr("alice");

    function setUp() public {
        nvnm = new MockERC20("NVNM", "NVNM");
        usd = new MockERC20("nvmnUSD", "nvmnUSD");
        staking = NVNMStaking(LibClone.deployERC1967(address(new NVNMStaking())));
        staking.initialize(owner, address(nvnm), address(usd));
        factory = new FeeRouterFactory(address(staking), owner, 2000); // cap commission at 20%
        router = FeeRouter(factory.create(validator, operator, 1000, 0)); // 10% commission

        nvnm.mint(alice, 1000 ether);
        vm.prank(alice);
        nvnm.approve(address(staking), type(uint256).max);
    }

    function _stake(uint256 amount) internal {
        vm.prank(alice);
        staking.stake(validator, amount);
    }

    function test_flush_splitsCommissionAndDeposits() public {
        _stake(100 ether);
        usd.mint(address(router), 100 ether); // stands in for FeeManager.distributeFees payout

        vm.prank(makeAddr("keeper")); // permissionless
        assertEq(router.flush(), 90 ether);
        assertEq(usd.balanceOf(operator), 10 ether);
        assertEq(staking.earned(validator, alice), 90 ether);
        assertEq(usd.balanceOf(address(router)), 0);
    }

    function test_flush_holdsUntilPoolHasStakers() public {
        usd.mint(address(router), 100 ether);
        assertEq(router.flush(), 0);
        // Nothing moved — including no commission, so held funds are never double-charged.
        assertEq(usd.balanceOf(address(router)), 100 ether);
        assertEq(usd.balanceOf(operator), 0);

        _stake(1 ether);
        assertEq(router.flush(), 90 ether);
    }

    function test_flush_zeroBalanceIsNoop() public {
        _stake(1 ether);
        assertEq(router.flush(), 0);
    }

    function test_flush_commissionExtremes() public {
        _stake(1 ether);
        FeeRouter zero = FeeRouter(factory.create(validator, operator, 0, 0));
        usd.mint(address(zero), 50 ether);
        assertEq(zero.flush(), 50 ether); // all to stakers

        FeeRouter all = new FeeRouter(validator, operator, address(staking), address(0), 10_000, 0);
        usd.mint(address(all), 50 ether);
        assertEq(all.flush(), 0); // all to operator
        assertEq(usd.balanceOf(operator), 50 ether);
    }

    function test_factory_enforcesCommissionCap() public {
        vm.expectRevert(FeeRouterFactory.CommissionTooHigh.selector);
        factory.create(validator, operator, 2001, 0);

        factory.create(validator, operator, 2000, 0); // at the cap: fine

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setMaxCommission(500);

        vm.prank(owner);
        factory.setMaxCommission(500);
        vm.expectRevert(FeeRouterFactory.CommissionTooHigh.selector);
        factory.create(validator, operator, 501, 0);
    }

    function test_flush_buysBackAndCompounds() public {
        MockSwapPool pool = new MockSwapPool(address(usd), address(nvnm));
        usd.mint(address(pool), 1000 ether);
        nvnm.mint(address(pool), 1000 ether);
        vm.prank(owner);
        factory.setSwapper(address(pool));

        FeeRouter r = FeeRouter(factory.create(validator, operator, 1000, 4000)); // 10% + 40%
        _stake(100 ether);
        usd.mint(address(r), 100 ether);

        uint256 expectedOut = (uint256(1000 ether) * 40 ether) / uint256(1040 ether); // x*y=k, no fee
        assertEq(r.flush(), 50 ether); // deposited remainder
        assertEq(usd.balanceOf(operator), 10 ether);
        assertEq(staking.earned(validator, alice), 50 ether);
        // 1 wei tolerance: the staking pool's virtual-offset share rate rounds in the pool's favor.
        assertApproxEqAbs(
            staking.stakedOf(validator, alice), 100 ether + expectedOut, 1, "buyback compounded"
        );
    }

    function test_flush_withoutSwapper_foldsBuybackIntoDeposit() public {
        FeeRouter r = FeeRouter(factory.create(validator, operator, 1000, 4000));
        _stake(100 ether);
        usd.mint(address(r), 100 ether);

        assertEq(r.flush(), 90 ether, "buyback folds into deposit until a market exists");
        assertEq(staking.earned(validator, alice), 90 ether);
    }

    function test_constructor_validation() public {
        vm.expectRevert(FeeRouter.ZeroAddress.selector);
        new FeeRouter(address(0), operator, address(staking), address(0), 0, 0);
        vm.expectRevert(FeeRouter.InvalidBps.selector);
        new FeeRouter(validator, operator, address(staking), address(0), 6000, 5000); // sum > 100%
    }

    function test_sweep_rescuesFundsFromCollapsedPool() public {
        _stake(100 ether);
        usd.mint(address(router), 100 ether);

        // A 100% slash permanently collapses the pool: totalStaked can never return to nonzero,
        // so flush() is stuck at 0 and the fees would be stranded.
        vm.prank(owner);
        staking.slash(validator, 10_000, makeAddr("treasury"));
        assertEq(router.flush(), 0);

        // Only the factory owner can sweep, and it recovers the stranded balance.
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(FeeRouter.NotFactoryOwner.selector);
        router.sweep(address(usd), operator);

        vm.prank(owner);
        assertEq(router.sweep(address(usd), operator), 100 ether);
        assertEq(usd.balanceOf(operator), 100 ether);
        assertEq(usd.balanceOf(address(router)), 0);
    }

    function test_sweep_unreachableForFactorylessRouter() public {
        FeeRouter r = new FeeRouter(validator, operator, address(staking), address(0), 0, 0);
        usd.mint(address(r), 1 ether);
        vm.prank(owner);
        vm.expectRevert(FeeRouter.NotFactoryOwner.selector);
        r.sweep(address(usd), operator);
    }

    function test_flush_dustBuybackDoesNotRevert() public {
        // A swapper that returns 0 for a tiny buyback must not brick the whole flush: the
        // commission and stable-deposit legs still settle.
        MockSwapPool pool = new MockSwapPool(address(usd), address(nvnm));
        usd.mint(address(pool), 1000 ether);
        nvnm.mint(address(pool), 1000 ether);
        vm.prank(owner);
        factory.setSwapper(address(pool));

        FeeRouter r = FeeRouter(factory.create(validator, operator, 1000, 4000));
        _stake(100 ether);
        usd.mint(address(r), 2); // buyback = 0 (40% of 2 = 0 after truncation); no revert
        assertEq(r.flush(), 2); // whole balance minus zero commission/buyback deposited
    }

    function test_factory_constructorValidation() public {
        vm.expectRevert(FeeRouterFactory.ZeroAddress.selector);
        new FeeRouterFactory(address(0), owner, 2000);
        vm.expectRevert(FeeRouterFactory.CommissionTooHigh.selector);
        new FeeRouterFactory(address(staking), owner, 10_001);
    }

    function test_factory_isDeterministicPerParams() public {
        // Same params redeploy reverts (CREATE2 collision); different params get a new router.
        vm.expectRevert();
        factory.create(validator, operator, 1000, 0);
        address other = factory.create(validator, operator, 2000, 0);
        assertTrue(other != address(router));
        assertEq(FeeRouter(other).commissionBps(), 2000);
        assertEq(FeeRouter(other).rewardToken(), address(usd));
    }
}
