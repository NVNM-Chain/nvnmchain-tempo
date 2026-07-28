// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {FeeRouter, FeeRouterFactory} from "../src/FeeRouter.sol";
import {NVNMStaking} from "../src/NVNMStaking.sol";
import {MockERC20} from "./support/MockERC20.sol";

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
        factory = new FeeRouterFactory(address(staking), owner, 2_000); // cap commission at 20%
        router = FeeRouter(factory.create(validator, operator, 1_000)); // 10% commission

        nvnm.mint(alice, 1_000 ether);
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
        FeeRouter zero = FeeRouter(factory.create(validator, operator, 0));
        usd.mint(address(zero), 50 ether);
        assertEq(zero.flush(), 50 ether); // all to stakers

        FeeRouter all = new FeeRouter(validator, operator, address(staking), 10_000);
        usd.mint(address(all), 50 ether);
        assertEq(all.flush(), 0); // all to operator
        assertEq(usd.balanceOf(operator), 50 ether);
    }

    function test_factory_enforcesCommissionCap() public {
        vm.expectRevert(FeeRouterFactory.CommissionTooHigh.selector);
        factory.create(validator, operator, 2_001);

        factory.create(validator, operator, 2_000); // at the cap: fine

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setMaxCommission(500);

        vm.prank(owner);
        factory.setMaxCommission(500);
        vm.expectRevert(FeeRouterFactory.CommissionTooHigh.selector);
        factory.create(validator, operator, 501);
    }

    function test_constructor_validation() public {
        vm.expectRevert(FeeRouter.ZeroAddress.selector);
        new FeeRouter(address(0), operator, address(staking), 0);
        vm.expectRevert(FeeRouter.InvalidBps.selector);
        new FeeRouter(validator, operator, address(staking), 10_001);
    }

    function test_factory_isDeterministicPerParams() public {
        // Same params redeploy reverts (CREATE2 collision); different params get a new router.
        vm.expectRevert();
        factory.create(validator, operator, 1_000);
        address other = factory.create(validator, operator, 2_000);
        assertTrue(other != address(router));
        assertEq(FeeRouter(other).commissionBps(), 2_000);
        assertEq(FeeRouter(other).rewardToken(), address(usd));
    }
}
