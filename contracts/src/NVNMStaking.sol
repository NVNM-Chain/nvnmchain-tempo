// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Ownable } from "solady/auth/Ownable.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { Initializable } from "solady/utils/Initializable.sol";
import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/// @title NVNMStaking
/// @notice Delegated fee-sharing staking: stake NVNM toward a validator, and that validator's
///         deposited stablecoin fees are split pro-rata among its stakers. Rewards are deposited,
///         never minted (fixed-supply token).
/// @dev UUPS proxy, `owner` (a Safe) is the upgrade authority. Stake is accounted in
///      shares per validator pool, so `slash` cuts every delegator pro-rata in O(1); pending
///      (unbonding) stake is slashable via a per-validator factor. `slash` is callable by the
///      protocol system caller (address(0)) or the owner. Unstaking is subject to the owner-set
///      unbonding period (see `unstake` / `withdraw`).
contract NVNMStaking is UUPSUpgradeable, Initializable, Ownable, ReentrancyGuard {
    using FixedPointMathLib for uint256;

    uint256 private constant ACC = 1e18; // fixed-point scale (reward accumulator, pending factor)
    uint256 private constant BPS = 10_000;
    // ERC4626-style virtual offset: the share rate is (tShares + VIRTUAL_SHARES) per
    // (tStaked + VIRTUAL_STAKE), so inflating the rate via `compoundReward` donations costs the
    // attacker more than any victim's rounding loss — first-depositor share-inflation is
    // unprofitable by construction. Virtual shares earn nothing real: they only absorb dust.
    uint256 private constant VIRTUAL_SHARES = 1e6;
    uint256 private constant VIRTUAL_STAKE = 1;
    uint256 private constant MAX_CANDIDATES = 256; // bounds the consensus-facing election scan

    // -- ERC-7201 namespaced storage -----------------------------------------
    /// @custom:storage-location erc7201:nvnm.staking.storage
    struct StakingStorage {
        address stakeToken; // NVNM
        address rewardToken; // fee stablecoin (nvmnUSD)
        mapping(address => uint256) totalStaked; // validator => live pool tokens (cut by slash)
        mapping(address => uint256) accRewardPerShare; // validator => reward accumulator (per share, scaled by ACC)
        mapping(address => mapping(address => uint256)) shares; // validator => user => pool shares
        mapping(address => uint256) totalShares; // validator => total pool shares
        mapping(address => mapping(address => uint256)) userPaid; // validator => user => acc at last settle
        mapping(address => mapping(address => uint256)) accrued; // validator => user => claimable rewards
        // committee election (quantized multi-seat)
        address[] candidates; // owner-curated electable validators (bounds election cost)
        mapping(address => bool) isCandidate;
        uint256 tokensPerSeat; // stake per seat; 0 = election unconfigured
        uint256 maxSeats; // total seat budget per committee
        uint256 maxSeatsPerValidator; // anti-concentration cap
        // unbonding: exiting stake stops earning and stops counting for election immediately,
        // but is only withdrawable after the delay; it remains slashable via `pendingFactor`
        uint256 unbondingPeriod; // seconds; 0 = immediate unstake
        mapping(address => mapping(address => uint256)) pendingNorm; // validator => user => normalized pending
        mapping(address => mapping(address => uint256)) unstakeReleaseAt; // validator => user => timestamp
        mapping(address => uint256) totalPendingNorm; // validator => total normalized pending
        mapping(address => uint256) pendingFactor; // validator => slash factor (ACC-scaled; 0 = ACC)
        // bonded candidacy: permissionless self-registration, bounded by an NVNM bond
        uint256 candidacyBond; // 0 = self-registration closed (owner curation only)
        mapping(address => uint256) bondPaid; // candidate => bond held (refunded on exit)
    }

    // keccak256(abi.encode(uint256(keccak256("nvnm.staking.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT =
        0x30ce8c2903d30a857154c6ccc6fd0f005695d28f4395deb97f28581bda922200;

    function _s() private pure returns (StakingStorage storage $) {
        assembly {
            $.slot := _STORAGE_SLOT
        }
    }

    // -- events --------------------------------------------------------------
    event Staked(address indexed validator, address indexed user, uint256 amount);
    event Unstaked(address indexed validator, address indexed user, uint256 amount);
    event RewardDeposited(address indexed validator, address indexed from, uint256 amount);
    event RewardClaimed(address indexed validator, address indexed user, uint256 amount);
    event CandidateSet(address indexed validator, bool active);
    event SeatConfigSet(uint256 tokensPerSeat, uint256 maxSeats, uint256 maxSeatsPerValidator);
    event CandidacyBondSet(uint256 bond);
    event UnstakeRequested(
        address indexed validator, address indexed user, uint256 amount, uint256 releaseAt
    );
    event Withdrawn(address indexed validator, address indexed user, uint256 amount);
    event UnbondingPeriodSet(uint256 period);
    event Slashed(
        address indexed validator, uint256 bps, uint256 seized, address indexed recipient
    );
    event RewardCompounded(address indexed validator, address indexed from, uint256 amount);

    // -- errors --------------------------------------------------------------
    error ZeroAmount();
    error ZeroAddress();
    error InsufficientStake();
    error NoStakers();
    error NotConfigured();
    error AlreadyCandidate();
    error NotCandidate();
    error InvalidPeriod();
    error NothingToWithdraw();
    error StillUnbonding();
    error CandidacyClosed();
    error InvalidBps();
    error NotAuthorized();
    error PoolCollapsed();
    error ZeroShares();
    error CandidateListFull();

    constructor() {
        _disableInitializers();
    }

    /// @dev Tokens must be standard ERC-20s (no fee-on-transfer / rebasing).
    function initialize(address owner_, address stakeToken_, address rewardToken_)
        external
        initializer
    {
        if (stakeToken_ == address(0) || rewardToken_ == address(0)) revert ZeroAddress();
        _initializeOwner(owner_);
        StakingStorage storage $ = _s();
        $.stakeToken = stakeToken_;
        $.rewardToken = rewardToken_;
    }

    // -- staking -------------------------------------------------------------
    /// @notice Stake `amount` NVNM toward `validator`, minting pool shares at the current rate.
    function stake(address validator, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        StakingStorage storage $ = _s();
        uint256 tShares = $.totalShares[validator];
        uint256 tStaked = $.totalStaked[validator];
        // A fully-slashed pool (shares outstanding, zero tokens) has no meaningful rate.
        if (tShares != 0 && tStaked == 0) revert PoolCollapsed();
        uint256 minted = amount.fullMulDiv(tShares + VIRTUAL_SHARES, tStaked + VIRTUAL_STAKE);
        if (minted == 0) revert ZeroShares(); // backstop: rate pushed beyond the virtual offset
        _settle($, validator, msg.sender);
        $.shares[validator][msg.sender] += minted;
        $.totalShares[validator] = tShares + minted;
        $.totalStaked[validator] = tStaked + amount;
        SafeTransferLib.safeTransferFrom($.stakeToken, msg.sender, address(this), amount);
        emit Staked(validator, msg.sender, amount);
    }

    /// @notice Exit `amount` tokens of your stake from `validator` (accrued rewards stay
    ///         claimable). With an unbonding period set, the stake moves to a pending bucket
    ///         withdrawable via `withdraw` after the delay — still slashable there; a new
    ///         request resets the clock on the whole bucket.
    function unstake(address validator, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        StakingStorage storage $ = _s();
        uint256 tShares = $.totalShares[validator];
        uint256 tStaked = $.totalStaked[validator];
        uint256 userShares = $.shares[validator][msg.sender];
        if (
            tStaked == 0
                || userShares.fullMulDiv(tStaked + VIRTUAL_STAKE, tShares + VIRTUAL_SHARES) < amount
        ) {
            revert InsufficientStake();
        }
        // Burn rounded-up shares so the pool never pays out more than the share fraction.
        uint256 burned = amount.fullMulDivUp(tShares + VIRTUAL_SHARES, tStaked + VIRTUAL_STAKE);
        if (burned > userShares) burned = userShares;
        _settle($, validator, msg.sender);
        $.shares[validator][msg.sender] = userShares - burned;
        $.totalShares[validator] = tShares - burned;
        $.totalStaked[validator] = tStaked - amount;
        uint256 period = $.unbondingPeriod;
        if (period == 0) {
            SafeTransferLib.safeTransfer($.stakeToken, msg.sender, amount);
            emit Unstaked(validator, msg.sender, amount);
        } else {
            uint256 releaseAt = block.timestamp + period;
            uint256 norm = amount.fullMulDiv(ACC, _pendingFactor($, validator));
            $.pendingNorm[validator][msg.sender] += norm;
            $.totalPendingNorm[validator] += norm;
            $.unstakeReleaseAt[validator][msg.sender] = releaseAt;
            emit UnstakeRequested(validator, msg.sender, amount, releaseAt);
        }
    }

    /// @notice Withdraw your matured unbonding stake from `validator` (net of any slashing).
    function withdraw(address validator) external nonReentrant returns (uint256 amount) {
        StakingStorage storage $ = _s();
        uint256 norm = $.pendingNorm[validator][msg.sender];
        if (norm == 0) revert NothingToWithdraw();
        if (block.timestamp < $.unstakeReleaseAt[validator][msg.sender]) revert StillUnbonding();
        $.pendingNorm[validator][msg.sender] = 0;
        $.totalPendingNorm[validator] -= norm;
        amount = norm.fullMulDiv(_pendingFactor($, validator), ACC);
        if (amount != 0) SafeTransferLib.safeTransfer($.stakeToken, msg.sender, amount);
        emit Withdrawn(validator, msg.sender, amount);
    }

    /// @notice Set the unbonding delay (only affects future unstakes). Should be at least one
    ///         epoch once the committee election feeds consensus.
    function setUnbondingPeriod(uint256 period) external onlyOwner {
        if (period > 30 days) revert InvalidPeriod();
        _s().unbondingPeriod = period;
        emit UnbondingPeriodSet(period);
    }

    /// @notice Deposit `amount` of reward token to split pro-rata among `validator`'s stakers.
    ///         Permissionless — the fee-routing layer (or anyone) tops up a validator's pool.
    function depositReward(address validator, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        StakingStorage storage $ = _s();
        uint256 tShares = $.totalShares[validator];
        if (tShares == 0) revert NoStakers();
        SafeTransferLib.safeTransferFrom($.rewardToken, msg.sender, address(this), amount);
        $.accRewardPerShare[validator] += (amount * ACC) / tShares;
        emit RewardDeposited(validator, msg.sender, amount);
    }

    /// @notice Add stake tokens to `validator`'s pool without minting shares: every delegator's
    ///         stake grows pro-rata. The hook for compounding fee-buyback NVNM (raw transfers are
    ///         ignored by the accounting, so compounding must be explicit). Permissionless — the
    ///         virtual-offset share rate makes donation-based rate inflation unprofitable.
    function compoundReward(address validator, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        StakingStorage storage $ = _s();
        if ($.totalShares[validator] == 0) revert NoStakers();
        if ($.totalStaked[validator] == 0) revert PoolCollapsed(); // don't revive a fully-slashed pool
        $.totalStaked[validator] += amount;
        SafeTransferLib.safeTransferFrom($.stakeToken, msg.sender, address(this), amount);
        emit RewardCompounded(validator, msg.sender, amount);
    }

    /// @notice Claim your accrued reward-token rewards for `validator`.
    function claim(address validator) external nonReentrant returns (uint256 amount) {
        StakingStorage storage $ = _s();
        _settle($, validator, msg.sender);
        amount = $.accrued[validator][msg.sender];
        if (amount != 0) {
            $.accrued[validator][msg.sender] = 0;
            SafeTransferLib.safeTransfer($.rewardToken, msg.sender, amount);
            emit RewardClaimed(validator, msg.sender, amount);
        }
    }

    // -- slashing ------------------------------------------------------------
    /// @notice Slash `bps` of `validator`'s pool — live and unbonding stake alike, pro-rata
    ///         across all delegators in O(1), plus the validator's full candidacy bond —
    ///         transferring the seized NVNM to `recipient`.
    /// @dev Callable by the protocol system caller (address(0), the sender tempo uses for
    ///      system transactions) or by the owner (governance slashing; removed at ossification).
    function slash(address validator, uint256 bps, address recipient)
        external
        nonReentrant
        returns (uint256 seized)
    {
        if (msg.sender != address(0) && msg.sender != owner()) revert NotAuthorized();
        if (bps == 0 || bps > BPS) revert InvalidBps();
        if (recipient == address(0)) revert ZeroAddress();
        StakingStorage storage $ = _s();

        // Live pool: cut the token total; shares are untouched so every delegator eats bps.
        uint256 liveCut = ($.totalStaked[validator] * bps) / BPS;
        $.totalStaked[validator] -= liveCut;

        // Pending pool: cut the factor; every pending withdrawal shrinks by bps.
        uint256 factor = _pendingFactor($, validator);
        uint256 poolBefore = $.totalPendingNorm[validator].fullMulDiv(factor, ACC);
        uint256 newFactor = (factor * (BPS - bps)) / BPS;
        $.pendingFactor[validator] = newFactor == 0 ? 1 : newFactor; // 1 wei floor: 0 means "unset"
        uint256 poolAfter =
            $.totalPendingNorm[validator].fullMulDiv($.pendingFactor[validator], ACC);

        // Any slash forfeits the full candidacy bond — the validator's own skin in the game.
        uint256 bond = $.bondPaid[validator];
        if (bond != 0) $.bondPaid[validator] = 0;

        seized = liveCut + (poolBefore - poolAfter) + bond;
        if (seized != 0) SafeTransferLib.safeTransfer($.stakeToken, recipient, seized);
        emit Slashed(validator, bps, seized, recipient);
    }

    /// @dev Fold pending rewards into `accrued` and mark the user settled to the current accumulator.
    function _settle(StakingStorage storage $, address validator, address user) private {
        uint256 acc = $.accRewardPerShare[validator];
        $.accrued[
                validator
            ][user] += ($.shares[validator][user] * (acc - $.userPaid[validator][user])) / ACC;
        $.userPaid[validator][user] = acc;
    }

    /// @dev The pending-bucket slash factor (ACC-scaled); an unset slot means "never slashed".
    function _pendingFactor(StakingStorage storage $, address validator)
        private
        view
        returns (uint256 f)
    {
        f = $.pendingFactor[validator];
        if (f == 0) f = ACC;
    }

    // -- committee election (quantized multi-seat) ---------------------------
    // The weighted-PoS selection function: seats_i = min(totalStaked_i / tokensPerSeat, cap),
    // ranked by stake and truncated to the maxSeats budget. One seat = one DKG share, so voting
    // power approximates stake while staying compatible with the unit-weighted threshold engine.
    // Candidacy is owner-curated or self-registered against an NVNM bond — both bound the
    // election list. A consumer (e.g. the consensus layer) reads `computeCommittee()` at a
    // chosen block; that read is itself the stake snapshot.

    /// @notice Add or remove an electable validator (owner curation; no bond involved on add,
    ///         any held bond is refunded on removal).
    function setCandidate(address validator, bool active) external onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        if (active) {
            _addCandidate(validator);
        } else {
            _removeCandidate(validator);
        }
    }

    /// @notice Self-register as an electable validator by posting the NVNM candidacy bond.
    function registerCandidate() external nonReentrant {
        StakingStorage storage $ = _s();
        uint256 bond = $.candidacyBond;
        if (bond == 0) revert CandidacyClosed();
        // The consensus layer eth_calls computeCommittee() each epoch under a fixed gas budget;
        // an unbounded self-registered list would let bond capital grief that read into fallback.
        if ($.candidates.length >= MAX_CANDIDATES) revert CandidateListFull();
        $.bondPaid[msg.sender] = bond;
        _addCandidate(msg.sender);
        SafeTransferLib.safeTransferFrom($.stakeToken, msg.sender, address(this), bond);
    }

    /// @notice Resign candidacy; the held bond is refunded.
    function resignCandidate() external nonReentrant {
        _removeCandidate(msg.sender);
    }

    /// @notice Set the NVNM bond for permissionless candidacy (0 closes self-registration).
    function setCandidacyBond(uint256 bond) external onlyOwner {
        _s().candidacyBond = bond;
        emit CandidacyBondSet(bond);
    }

    function _addCandidate(address validator) private {
        StakingStorage storage $ = _s();
        if ($.isCandidate[validator]) revert AlreadyCandidate();
        $.isCandidate[validator] = true;
        $.candidates.push(validator);
        emit CandidateSet(validator, true);
    }

    /// @dev Removes `validator` from the electable list and refunds any held bond.
    function _removeCandidate(address validator) private {
        StakingStorage storage $ = _s();
        if (!$.isCandidate[validator]) revert NotCandidate();
        $.isCandidate[validator] = false;
        address[] storage list = $.candidates;
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == validator) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }
        emit CandidateSet(validator, false);
        uint256 bond = $.bondPaid[validator];
        if (bond != 0) {
            $.bondPaid[validator] = 0;
            SafeTransferLib.safeTransfer($.stakeToken, validator, bond);
        }
    }

    /// @notice Configure the election: stake per seat, total seat budget, per-validator cap.
    function setSeatConfig(uint256 tokensPerSeat_, uint256 maxSeats_, uint256 maxSeatsPerValidator_)
        external
        onlyOwner
    {
        if (tokensPerSeat_ == 0 || maxSeats_ == 0 || maxSeatsPerValidator_ == 0) {
            revert ZeroAmount();
        }
        StakingStorage storage $ = _s();
        $.tokensPerSeat = tokensPerSeat_;
        $.maxSeats = maxSeats_;
        $.maxSeatsPerValidator = maxSeatsPerValidator_;
        emit SeatConfigSet(tokensPerSeat_, maxSeats_, maxSeatsPerValidator_);
    }

    /// @notice The elected committee at the current state: candidates with >= 1 seat, ranked by
    ///         stake (stable on ties), seats truncated to the `maxSeats` budget.
    function computeCommittee()
        external
        view
        returns (address[] memory vals, uint256[] memory seats)
    {
        StakingStorage storage $ = _s();
        uint256 per = $.tokensPerSeat;
        if (per == 0) revert NotConfigured();

        // Collect candidates with at least one seat.
        uint256 n = $.candidates.length;
        address[] memory cv = new address[](n);
        uint256[] memory cstake = new uint256[](n);
        uint256 m;
        for (uint256 i; i < n; ++i) {
            address c = $.candidates[i];
            if ($.totalStaked[c] >= per) {
                cv[m] = c;
                cstake[m] = $.totalStaked[c];
                ++m;
            }
        }

        // Stable insertion sort by stake, descending (m is bounded: owner curation plus the
        // MAX_CANDIDATES cap on bonded self-registration).
        for (uint256 i = 1; i < m; ++i) {
            address v = cv[i];
            uint256 s = cstake[i];
            uint256 j = i;
            for (; j > 0 && cstake[j - 1] < s; --j) {
                cv[j] = cv[j - 1];
                cstake[j] = cstake[j - 1];
            }
            cv[j] = v;
            cstake[j] = s;
        }

        // Allocate seats by rank until the budget runs out.
        uint256 cap = $.maxSeatsPerValidator;
        uint256 budget = $.maxSeats;
        uint256 count;
        uint256[] memory alloc = new uint256[](m);
        for (uint256 i; i < m && budget > 0; ++i) {
            uint256 s = cstake[i] / per;
            if (s > cap) s = cap;
            if (s > budget) s = budget;
            alloc[i] = s;
            budget -= s;
            ++count;
        }

        vals = new address[](count);
        seats = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            vals[i] = cv[i];
            seats[i] = alloc[i];
        }
    }

    function candidates() external view returns (address[] memory) {
        return _s().candidates;
    }

    function candidacyBond() external view returns (uint256) {
        return _s().candidacyBond;
    }

    function bondOf(address validator) external view returns (uint256) {
        return _s().bondPaid[validator];
    }

    function seatConfig()
        external
        view
        returns (uint256 tokensPerSeat, uint256 maxSeats, uint256 maxSeatsPerValidator)
    {
        StakingStorage storage $ = _s();
        return ($.tokensPerSeat, $.maxSeats, $.maxSeatsPerValidator);
    }

    // -- views ---------------------------------------------------------------
    /// @notice Claimable rewards for `user` on `validator`, including unsettled accrual.
    function earned(address validator, address user) external view returns (uint256) {
        StakingStorage storage $ = _s();
        uint256 pending =
            ($.shares[validator][user]
                    * ($.accRewardPerShare[validator] - $.userPaid[validator][user])) / ACC;
        return $.accrued[validator][user] + pending;
    }

    /// @notice `user`'s live stake in tokens at the pool's current rate (reflects slashing).
    function stakedOf(address validator, address user) external view returns (uint256) {
        StakingStorage storage $ = _s();
        uint256 tShares = $.totalShares[validator];
        if (tShares == 0) return 0;
        return $.shares[validator][user].fullMulDiv(
            $.totalStaked[validator] + VIRTUAL_STAKE, tShares + VIRTUAL_SHARES
        );
    }

    function sharesOf(address validator, address user) external view returns (uint256) {
        return _s().shares[validator][user];
    }

    function totalStaked(address validator) external view returns (uint256) {
        return _s().totalStaked[validator];
    }

    /// @notice Withdrawable pending stake in tokens (net of any slashing so far).
    function pendingUnstakeOf(address validator, address user)
        external
        view
        returns (uint256 amount, uint256 releaseAt)
    {
        StakingStorage storage $ = _s();
        amount = $.pendingNorm[validator][user].fullMulDiv(_pendingFactor($, validator), ACC);
        releaseAt = $.unstakeReleaseAt[validator][user];
    }

    function unbondingPeriod() external view returns (uint256) {
        return _s().unbondingPeriod;
    }

    function stakeToken() external view returns (address) {
        return _s().stakeToken;
    }

    function rewardToken() external view returns (address) {
        return _s().rewardToken;
    }

    // -- upgrade authority ---------------------------------------------------
    function _authorizeUpgrade(address) internal override onlyOwner { }

    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }
}
