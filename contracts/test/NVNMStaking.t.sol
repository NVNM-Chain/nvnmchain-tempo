// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { NVNMStaking } from "../src/NVNMStaking.sol";
import { MockERC20 } from "./support/MockERC20.sol";
import { Test } from "forge-std/Test.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { LibClone } from "solady/utils/LibClone.sol";

contract NVNMStakingV2 is NVNMStaking {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract NVNMStakingTest is Test {
    NVNMStaking staking;
    MockERC20 nvnm; // stake token
    MockERC20 usd; // reward token (fee stablecoin)

    address owner = makeAddr("safe");
    address validator = makeAddr("validator");
    address validator2 = makeAddr("validator2");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        nvnm = new MockERC20("NVNM", "NVNM");
        usd = new MockERC20("nvmnUSD", "nvmnUSD");
        address impl = address(new NVNMStaking());
        staking = NVNMStaking(LibClone.deployERC1967(impl));
        staking.initialize(owner, address(nvnm), address(usd));

        for (address who = alice;; who = bob) {
            nvnm.mint(who, 1000 ether);
            vm.prank(who);
            nvnm.approve(address(staking), type(uint256).max);
            if (who == bob) break;
        }
        // Reward depositor (stands in for the fee-routing layer).
        usd.mint(address(this), 1_000_000 ether);
        usd.approve(address(staking), type(uint256).max);
    }

    function _stake(address who, address val, uint256 amt) internal {
        vm.prank(who);
        staking.stake(val, amt);
    }

    // -- staking basics ------------------------------------------------------
    function test_stake_and_unstake() public {
        _stake(alice, validator, 100 ether);
        assertEq(staking.stakedOf(validator, alice), 100 ether);
        assertEq(staking.totalStaked(validator), 100 ether);
        assertEq(nvnm.balanceOf(address(staking)), 100 ether);

        vm.prank(alice);
        staking.unstake(validator, 40 ether);
        assertEq(staking.stakedOf(validator, alice), 60 ether);
        assertEq(nvnm.balanceOf(alice), 940 ether);
    }

    function test_stake_zeroReverts() public {
        vm.prank(alice);
        vm.expectRevert(NVNMStaking.ZeroAmount.selector);
        staking.stake(validator, 0);
    }

    function test_unstake_moreThanStakedReverts() public {
        _stake(alice, validator, 100 ether);
        vm.prank(alice);
        vm.expectRevert(NVNMStaking.InsufficientStake.selector);
        staking.unstake(validator, 101 ether);
    }

    // -- reward distribution -------------------------------------------------
    function test_depositReward_noStakersReverts() public {
        vm.expectRevert(NVNMStaking.NoStakers.selector);
        staking.depositReward(validator, 100 ether);
    }

    function test_singleStaker_getsAllRewards() public {
        _stake(alice, validator, 100 ether);
        staking.depositReward(validator, 500 ether);
        assertEq(staking.earned(validator, alice), 500 ether);

        vm.prank(alice);
        uint256 claimed = staking.claim(validator);
        assertEq(claimed, 500 ether);
        assertEq(usd.balanceOf(alice), 500 ether);
        assertEq(staking.earned(validator, alice), 0);
    }

    function test_rewards_splitProRata() public {
        _stake(alice, validator, 300 ether);
        _stake(bob, validator, 100 ether); // 3:1
        staking.depositReward(validator, 400 ether);
        assertEq(staking.earned(validator, alice), 300 ether);
        assertEq(staking.earned(validator, bob), 100 ether);
    }

    function test_rewards_onlyCountStakeAtDepositTime() public {
        // alice stakes, reward #1 is hers alone; then bob joins, reward #2 splits.
        _stake(alice, validator, 100 ether);
        staking.depositReward(validator, 100 ether); // all alice
        _stake(bob, validator, 100 ether);
        staking.depositReward(validator, 100 ether); // 50/50

        assertEq(staking.earned(validator, alice), 150 ether);
        assertEq(staking.earned(validator, bob), 50 ether);
    }

    function test_stakingMore_doesNotStealPastRewards() public {
        _stake(alice, validator, 100 ether);
        staking.depositReward(validator, 100 ether); // alice earned 100
        _stake(alice, validator, 900 ether); // stake up AFTER the deposit
        // The pre-existing 100 must not be diluted or re-counted.
        assertEq(staking.earned(validator, alice), 100 ether);
        staking.depositReward(validator, 50 ether); // now on 1000 staked, still all alice
        assertEq(staking.earned(validator, alice), 150 ether);
    }

    function test_perValidator_isolation() public {
        _stake(alice, validator, 100 ether);
        _stake(bob, validator2, 100 ether);
        staking.depositReward(validator, 100 ether);
        // Only validator's stakers earn; validator2's pool is untouched.
        assertEq(staking.earned(validator, alice), 100 ether);
        assertEq(staking.earned(validator2, bob), 0);
    }

    function test_unstake_keepsAccruedClaimable() public {
        _stake(alice, validator, 100 ether);
        staking.depositReward(validator, 100 ether);
        vm.prank(alice);
        staking.unstake(validator, 100 ether); // fully exit
        // Accrued rewards survive the exit.
        assertEq(staking.earned(validator, alice), 100 ether);
        vm.prank(alice);
        assertEq(staking.claim(validator), 100 ether);
    }

    // -- compounding ---------------------------------------------------------
    function test_compoundReward_growsAllStakesProRata() public {
        _stake(alice, validator, 300 ether);
        _stake(bob, validator, 100 ether);
        nvnm.mint(address(this), 100 ether);
        nvnm.approve(address(staking), 100 ether);

        staking.compoundReward(validator, 100 ether); // e.g. fee-buyback proceeds
        // 1 wei tolerance: the virtual-offset share rate rounds in the pool's favor.
        assertApproxEqAbs(staking.stakedOf(validator, alice), 375 ether, 1, "3/4 of the growth");
        assertApproxEqAbs(staking.stakedOf(validator, bob), 125 ether, 1, "1/4 of the growth");
        // Shares and the stablecoin reward accumulator are untouched (first mint is scaled by
        // the 1e6 virtual-share offset).
        assertEq(staking.sharesOf(validator, alice), 300 ether * 1e6);
        assertEq(staking.earned(validator, alice), 0);
    }

    function test_compoundReward_noStakersReverts() public {
        nvnm.mint(address(this), 1 ether);
        nvnm.approve(address(staking), 1 ether);
        vm.expectRevert(NVNMStaking.NoStakers.selector);
        staking.compoundReward(validator, 1 ether);
    }

    function test_compoundReward_collapsedPoolReverts() public {
        _stake(alice, validator, 100 ether);
        vm.prank(owner);
        staking.slash(validator, 10_000, treasury);

        nvnm.mint(address(this), 1 ether);
        nvnm.approve(address(staking), 1 ether);
        vm.expectRevert(NVNMStaking.PoolCollapsed.selector);
        staking.compoundReward(validator, 1 ether); // must not revive worthless shares
    }

    function test_stake_inflationAttackUnprofitable() public {
        // Classic first-depositor inflation: 1 wei stake, then a large donation via
        // compoundReward to push the share rate so the victim mints zero shares.
        address attacker = alice;
        address victim = bob;
        vm.startPrank(attacker);
        nvnm.approve(address(staking), type(uint256).max);
        staking.stake(validator, 1);
        staking.compoundReward(validator, 100 ether);
        vm.stopPrank();

        _stake(victim, validator, 100 ether);
        // The virtual offset keeps the victim's mint proportional: they must own ~half of the
        // ~200-ether pool, and the attacker cannot exit with more than they put in.
        assertApproxEqRel(staking.stakedOf(validator, victim), 100 ether, 1e12);
        uint256 attackerValue = staking.stakedOf(validator, attacker);
        assertLe(attackerValue, 100 ether + 1); // donation not recouped from the victim

        vm.prank(victim);
        staking.unstake(validator, 99.99 ether); // victim can exit ~all of their stake
    }

    function test_stake_zeroSharesBackstopReverts() public {
        // Push the rate past the virtual offset with tiny magnitudes: 1 wei staked, 3e6 wei
        // compounded → a 1-wei stake would mint 0 shares and must revert, not silently donate.
        vm.startPrank(alice);
        nvnm.approve(address(staking), type(uint256).max);
        staking.stake(validator, 1);
        staking.compoundReward(validator, 3e6);
        vm.stopPrank();

        vm.startPrank(bob);
        nvnm.approve(address(staking), 1);
        vm.expectRevert(NVNMStaking.ZeroShares.selector);
        staking.stake(validator, 1);
        vm.stopPrank();
    }

    function test_candidacy_registrationCapped() public {
        vm.prank(owner);
        staking.setCandidacyBond(1 ether);
        for (uint256 i; i < 256; ++i) {
            address c = address(uint160(0x10000 + i));
            nvnm.mint(c, 1 ether);
            vm.startPrank(c);
            nvnm.approve(address(staking), 1 ether);
            staking.registerCandidate();
            vm.stopPrank();
        }
        nvnm.mint(alice, 1 ether);
        vm.startPrank(alice);
        nvnm.approve(address(staking), 1 ether);
        vm.expectRevert(NVNMStaking.CandidateListFull.selector);
        staking.registerCandidate();
        vm.stopPrank();
    }

    // -- committee election --------------------------------------------------
    function _electionSetup() internal {
        vm.startPrank(owner);
        staking.setCandidate(validator, true);
        staking.setCandidate(validator2, true);
        staking.setSeatConfig(100 ether, 10, 5); // 100 NVNM per seat, 10 total, cap 5
        vm.stopPrank();
    }

    function test_election_quantizesStakeIntoSeats() public {
        _electionSetup();
        _stake(alice, validator, 300 ether); // 3 seats
        _stake(bob, validator2, 150 ether); // 1 seat (150/100 floors)

        (address[] memory vals, uint256[] memory seats) = staking.computeCommittee();
        assertEq(vals.length, 2);
        assertEq(vals[0], validator); // ranked by stake desc
        assertEq(seats[0], 3);
        assertEq(vals[1], validator2);
        assertEq(seats[1], 1);
    }

    function test_election_capsSeatsPerValidator() public {
        _electionSetup();
        _stake(alice, validator, 900 ether); // 9 seats uncapped -> capped to 5
        (, uint256[] memory seats) = staking.computeCommittee();
        assertEq(seats[0], 5);
    }

    function test_election_respectsSeatBudget() public {
        _electionSetup();
        vm.prank(owner);
        staking.setSeatConfig(100 ether, 4, 5); // budget 4
        _stake(alice, validator, 300 ether); // wants 3
        _stake(bob, validator2, 200 ether); // wants 2 -> truncated to 1

        (address[] memory vals, uint256[] memory seats) = staking.computeCommittee();
        assertEq(vals.length, 2);
        assertEq(seats[0], 3);
        assertEq(seats[1], 1); // budget exhausted
    }

    function test_election_excludesBelowOneSeatAndNonCandidates() public {
        _electionSetup();
        _stake(alice, validator, 99 ether); // below tokensPerSeat -> no seat
        address stranger = makeAddr("nonCandidate");
        _stake(bob, stranger, 500 ether); // staked but not a candidate

        (address[] memory vals,) = staking.computeCommittee();
        assertEq(vals.length, 0);
    }

    function test_election_unconfiguredReverts() public {
        vm.expectRevert(NVNMStaking.NotConfigured.selector);
        staking.computeCommittee();
    }

    function test_election_candidateManagement() public {
        vm.prank(owner);
        staking.setCandidate(validator, true);
        assertEq(staking.candidates().length, 1);

        vm.prank(owner);
        vm.expectRevert(NVNMStaking.AlreadyCandidate.selector);
        staking.setCandidate(validator, true);

        vm.prank(owner);
        staking.setCandidate(validator, false);
        assertEq(staking.candidates().length, 0);

        // Removed candidate no longer electable even with stake.
        vm.startPrank(owner);
        staking.setSeatConfig(100 ether, 10, 5);
        vm.stopPrank();
        _stake(alice, validator, 300 ether);
        (address[] memory vals,) = staking.computeCommittee();
        assertEq(vals.length, 0);
    }

    function test_election_onlyOwnerConfigures() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staking.setCandidate(validator, true);

        vm.prank(stranger);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staking.setSeatConfig(1, 1, 1);
    }

    // -- bonded candidacy ----------------------------------------------------
    function test_candidacy_registerWithBond() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);

        vm.prank(alice);
        staking.registerCandidate();
        assertTrue(staking.candidates().length == 1 && staking.candidates()[0] == alice);
        assertEq(staking.bondOf(alice), 50 ether);
        assertEq(nvnm.balanceOf(alice), 950 ether);

        // Electable like any curated candidate.
        vm.prank(owner);
        staking.setSeatConfig(100 ether, 10, 5);
        _stake(bob, alice, 100 ether);
        (address[] memory vals,) = staking.computeCommittee();
        assertEq(vals[0], alice);
    }

    function test_candidacy_closedWithoutBondConfig() public {
        vm.prank(alice);
        vm.expectRevert(NVNMStaking.CandidacyClosed.selector);
        staking.registerCandidate();
    }

    function test_candidacy_resignRefundsBond() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);
        vm.prank(alice);
        staking.registerCandidate();

        vm.prank(alice);
        staking.resignCandidate();
        assertEq(staking.candidates().length, 0);
        assertEq(staking.bondOf(alice), 0);
        assertEq(nvnm.balanceOf(alice), 1000 ether);
    }

    function test_candidacy_ownerKickRefundsBond() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);
        vm.prank(alice);
        staking.registerCandidate();

        vm.prank(owner);
        staking.setCandidate(alice, false);
        assertEq(nvnm.balanceOf(alice), 1000 ether, "kicked candidate gets bond back");
    }

    function test_candidacy_bondChangeDoesNotAffectHeldBonds() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);
        vm.prank(alice);
        staking.registerCandidate();

        vm.prank(owner);
        staking.setCandidacyBond(500 ether); // raise after alice registered
        vm.prank(alice);
        staking.resignCandidate();
        assertEq(nvnm.balanceOf(alice), 1000 ether, "refund is the bond actually paid");
    }

    function test_candidacy_duplicateAndNonCandidateRevert() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);
        vm.prank(alice);
        staking.registerCandidate();

        vm.prank(alice);
        vm.expectRevert(NVNMStaking.AlreadyCandidate.selector);
        staking.registerCandidate();

        vm.prank(bob);
        vm.expectRevert(NVNMStaking.NotCandidate.selector);
        staking.resignCandidate();
    }

    // -- unbonding -----------------------------------------------------------
    function test_unbonding_zeroPeriod_isImmediate() public {
        // Default period 0: unstake pays out instantly (covered above; assert explicitly).
        _stake(alice, validator, 100 ether);
        vm.prank(alice);
        staking.unstake(validator, 100 ether);
        assertEq(nvnm.balanceOf(alice), 1000 ether);
    }

    function test_unbonding_delaysWithdrawal() public {
        vm.prank(owner);
        staking.setUnbondingPeriod(7 days);
        _stake(alice, validator, 100 ether);

        vm.prank(alice);
        staking.unstake(validator, 100 ether);
        assertEq(nvnm.balanceOf(alice), 900 ether, "no instant payout");
        (uint256 amount, uint256 releaseAt) = staking.pendingUnstakeOf(validator, alice);
        assertEq(amount, 100 ether);
        assertEq(releaseAt, block.timestamp + 7 days);

        vm.prank(alice);
        vm.expectRevert(NVNMStaking.StillUnbonding.selector);
        staking.withdraw(validator);

        vm.warp(block.timestamp + 7 days);
        vm.prank(alice);
        assertEq(staking.withdraw(validator), 100 ether);
        assertEq(nvnm.balanceOf(alice), 1000 ether);
        (amount,) = staking.pendingUnstakeOf(validator, alice);
        assertEq(amount, 0);
    }

    function test_unbonding_newRequestResetsClock() public {
        // Absolute warps only: via-ir rematerializes TIMESTAMP, so reading block.timestamp
        // in test code after vm.warp is unreliable.
        uint256 t0 = 1_000_000;
        vm.warp(t0);
        vm.prank(owner);
        staking.setUnbondingPeriod(7 days);
        _stake(alice, validator, 200 ether);

        vm.prank(alice);
        staking.unstake(validator, 100 ether); // matures at t0 + 7d
        vm.warp(t0 + 6 days);
        vm.prank(alice);
        staking.unstake(validator, 100 ether); // resets the aggregate bucket to t0 + 13d

        vm.warp(t0 + 7 days); // first request alone would have matured; the bucket has not
        vm.prank(alice);
        vm.expectRevert(NVNMStaking.StillUnbonding.selector);
        staking.withdraw(validator);

        vm.warp(t0 + 13 days);
        vm.prank(alice);
        assertEq(staking.withdraw(validator), 200 ether);
    }

    function test_unbonding_stakeStopsEarningAndElecting() public {
        vm.startPrank(owner);
        staking.setUnbondingPeriod(7 days);
        staking.setCandidate(validator, true);
        staking.setSeatConfig(100 ether, 10, 5);
        vm.stopPrank();
        _stake(alice, validator, 100 ether);

        vm.prank(alice);
        staking.unstake(validator, 100 ether);
        // No longer elected...
        (address[] memory vals,) = staking.computeCommittee();
        assertEq(vals.length, 0);
        // ...and rewards can no longer be deposited toward it (no live stake).
        vm.expectRevert(NVNMStaking.NoStakers.selector);
        staking.depositReward(validator, 100 ether);
    }

    function test_unbonding_withdrawNothingReverts() public {
        vm.prank(alice);
        vm.expectRevert(NVNMStaking.NothingToWithdraw.selector);
        staking.withdraw(validator);
    }

    function test_unbonding_configAuthAndCap() public {
        vm.prank(alice);
        vm.expectRevert(Ownable.Unauthorized.selector);
        staking.setUnbondingPeriod(1 days);

        vm.prank(owner);
        vm.expectRevert(NVNMStaking.InvalidPeriod.selector);
        staking.setUnbondingPeriod(31 days);
    }

    // -- slashing ------------------------------------------------------------
    address treasury = makeAddr("treasury");

    function test_slash_cutsAllDelegatorsProRata() public {
        _stake(alice, validator, 300 ether);
        _stake(bob, validator, 100 ether);

        vm.prank(owner);
        uint256 seized = staking.slash(validator, 5000, treasury); // 50%
        assertEq(seized, 200 ether);
        assertEq(nvnm.balanceOf(treasury), 200 ether);
        assertEq(staking.stakedOf(validator, alice), 150 ether);
        assertEq(staking.stakedOf(validator, bob), 50 ether);
        assertEq(staking.totalStaked(validator), 200 ether);
    }

    function test_slash_systemCallerAllowed_strangerNot() public {
        _stake(alice, validator, 100 ether);

        vm.prank(bob);
        vm.expectRevert(NVNMStaking.NotAuthorized.selector);
        staking.slash(validator, 1000, treasury);

        vm.prank(address(0)); // the protocol system caller
        assertEq(staking.slash(validator, 1000, treasury), 10 ether);
    }

    function test_slash_hitsPendingBucket() public {
        vm.prank(owner);
        staking.setUnbondingPeriod(7 days);
        _stake(alice, validator, 100 ether);
        vm.prank(alice);
        staking.unstake(validator, 100 ether); // all pending

        vm.prank(owner);
        uint256 seized = staking.slash(validator, 5000, treasury);
        assertEq(seized, 50 ether, "pending stake is slashable");

        vm.warp(block.timestamp + 7 days);
        vm.prank(alice);
        assertEq(staking.withdraw(validator), 50 ether, "withdraw pays net of slash");
    }

    function test_slash_thenStake_ratesStayFair() public {
        _stake(alice, validator, 100 ether);
        vm.prank(owner);
        staking.slash(validator, 5000, treasury); // alice now effectively 50

        _stake(bob, validator, 100 ether); // joins post-slash at the new rate
        assertEq(staking.stakedOf(validator, alice), 50 ether, "old staker keeps the loss");
        assertApproxEqAbs(staking.stakedOf(validator, bob), 100 ether, 1, "new staker unaffected");

        // Rewards split by shares: alice ~1/3, bob ~2/3 (bob staked at the post-slash rate, so
        // holds ~2x alice's shares; virtual-offset rounding leaves a few wei of dust).
        staking.depositReward(validator, 300 ether);
        assertApproxEqAbs(staking.earned(validator, alice), 100 ether, 2);
        assertApproxEqAbs(staking.earned(validator, bob), 200 ether, 2);
    }

    function test_slash_full_collapsesPool() public {
        _stake(alice, validator, 100 ether);
        vm.prank(owner);
        staking.slash(validator, 10_000, treasury); // 100%

        assertEq(staking.stakedOf(validator, alice), 0);
        vm.prank(bob);
        vm.expectRevert(NVNMStaking.PoolCollapsed.selector);
        staking.stake(validator, 10 ether);
    }

    function test_slash_paramValidation() public {
        vm.startPrank(owner);
        vm.expectRevert(NVNMStaking.InvalidBps.selector);
        staking.slash(validator, 0, treasury);
        vm.expectRevert(NVNMStaking.InvalidBps.selector);
        staking.slash(validator, 10_001, treasury);
        vm.expectRevert(NVNMStaking.ZeroAddress.selector);
        staking.slash(validator, 1000, address(0));
        vm.stopPrank();
    }

    function test_slash_seizesCandidacyBond() public {
        vm.prank(owner);
        staking.setCandidacyBond(50 ether);
        nvnm.mint(validator, 50 ether);
        vm.startPrank(validator);
        nvnm.approve(address(staking), 50 ether);
        staking.registerCandidate();
        vm.stopPrank();
        _stake(alice, validator, 100 ether);

        vm.prank(owner);
        uint256 seized = staking.slash(validator, 5000, treasury);
        assertEq(seized, 50 ether + 50 ether, "half the pool plus the full bond");
        assertEq(staking.bondOf(validator), 0);

        // Resigning afterwards refunds nothing; administrative removal of an unslashed
        // candidate still would (bond only forfeits on slash).
        uint256 before = nvnm.balanceOf(validator);
        vm.prank(validator);
        staking.resignCandidate();
        assertEq(nvnm.balanceOf(validator), before);
    }

    function test_slash_reducesElectionSeats() public {
        vm.startPrank(owner);
        staking.setCandidate(validator, true);
        staking.setSeatConfig(100 ether, 10, 5);
        vm.stopPrank();
        _stake(alice, validator, 300 ether); // 3 seats

        vm.prank(owner);
        staking.slash(validator, 5000, treasury); // 150 left -> 1 seat
        (, uint256[] memory seats) = staking.computeCommittee();
        assertEq(seats[0], 1);
    }

    // -- lifecycle -----------------------------------------------------------
    function test_initialize_zeroTokenReverts() public {
        NVNMStaking fresh = NVNMStaking(LibClone.deployERC1967(address(new NVNMStaking())));
        vm.expectRevert(NVNMStaking.ZeroAddress.selector);
        fresh.initialize(owner, address(0), address(usd));
        vm.expectRevert(NVNMStaking.ZeroAddress.selector);
        fresh.initialize(owner, address(nvnm), address(0));
    }

    function test_upgrade_preservesStakeAndRewards_onlyOwner() public {
        _stake(alice, validator, 100 ether);
        staking.depositReward(validator, 100 ether);

        address v2 = address(new NVNMStakingV2());
        vm.prank(alice);
        vm.expectRevert(); // Ownable.Unauthorized
        staking.upgradeToAndCall(v2, "");

        vm.prank(owner);
        staking.upgradeToAndCall(v2, "");
        assertEq(NVNMStakingV2(address(staking)).version(), 2);
        assertEq(staking.stakedOf(validator, alice), 100 ether);
        assertEq(staking.earned(validator, alice), 100 ether);
    }
}
