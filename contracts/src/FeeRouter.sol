// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable} from "solady/auth/Ownable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

interface INVNMStaking {
    function depositReward(address validator, uint256 amount) external;
    function compoundReward(address validator, uint256 amount) external;
    function rewardToken() external view returns (address);
    function stakeToken() external view returns (address);
    function totalStaked(address validator) external view returns (uint256);
}

/// @notice A market that sells `tokenIn` for `tokenOut` (pulls `amountIn` from the caller).
interface ISwapper {
    function swap(address tokenIn, address tokenOut, uint256 amountIn, uint256 minOut)
        external
        returns (uint256 out);
}

/// @title FeeRouter
/// @notice Per-validator fee splitter. Set as the validator's fee recipient, it receives the
///         stablecoin fees paid out by the FeeManager's permissionless `distributeFees`;
///         `flush()` (also permissionless) pays the operator commission, buys NVNM with the
///         buyback portion and compounds it into the validator's pool, and deposits the rest
///         as stablecoin rewards. Without a factory swapper, the buyback folds into the deposit.
contract FeeRouter {
    uint256 private constant BPS = 10_000;

    address public immutable validator; // delegation key in the staking contract
    address public immutable operator; // receives the commission
    address public immutable staking;
    address public immutable factory; // source of the owner-set swapper
    address public immutable rewardToken;
    address public immutable stakeToken;
    uint256 public immutable commissionBps;
    uint256 public immutable buybackBps;

    event Flushed(uint256 commission, uint256 compounded, uint256 deposited);

    error ZeroAddress();
    error InvalidBps();

    constructor(
        address validator_,
        address operator_,
        address staking_,
        address factory_,
        uint256 commissionBps_,
        uint256 buybackBps_
    ) {
        if (validator_ == address(0) || operator_ == address(0) || staking_ == address(0)) revert ZeroAddress();
        if (commissionBps_ + buybackBps_ > BPS) revert InvalidBps();
        validator = validator_;
        operator = operator_;
        staking = staking_;
        factory = factory_;
        rewardToken = INVNMStaking(staking_).rewardToken();
        stakeToken = INVNMStaking(staking_).stakeToken();
        commissionBps = commissionBps_;
        buybackBps = buybackBps_;
    }

    /// @notice Split the router's reward-token balance: commission to the operator, buyback
    ///         compounded into the pool as NVNM, remainder deposited as stablecoin rewards.
    ///         No-op until the pool has stakers (balance is retained).
    function flush() external returns (uint256 deposited) {
        uint256 balance = SafeTransferLib.balanceOf(rewardToken, address(this));
        if (balance == 0 || INVNMStaking(staking).totalStaked(validator) == 0) return 0;

        uint256 commission = (balance * commissionBps) / BPS;
        if (commission != 0) SafeTransferLib.safeTransfer(rewardToken, operator, commission);

        uint256 buyback = (balance * buybackBps) / BPS;
        uint256 compounded;
        address swapper = factory == address(0) ? address(0) : FeeRouterFactory(factory).swapper();
        if (buyback != 0 && swapper != address(0)) {
            SafeTransferLib.safeApprove(rewardToken, swapper, buyback);
            compounded = ISwapper(swapper).swap(rewardToken, stakeToken, buyback, 0);
            SafeTransferLib.safeApprove(stakeToken, staking, compounded);
            INVNMStaking(staking).compoundReward(validator, compounded);
        } else {
            buyback = 0; // no market yet: fold into the stablecoin deposit
        }

        deposited = balance - commission - buyback;
        if (deposited != 0) {
            SafeTransferLib.safeApprove(rewardToken, staking, deposited);
            INVNMStaking(staking).depositReward(validator, deposited);
        }
        emit Flushed(commission, compounded, deposited);
    }
}

/// @notice Deploys one deterministic FeeRouter per (validator, operator, commission, buyback).
///         Validators self-serve within the owner-set commission bound; the owner also controls
///         which swap market (if any) buybacks execute on.
contract FeeRouterFactory is Ownable {
    address public immutable staking;
    uint256 public maxCommissionBps;
    address public swapper; // 0 = buybacks disabled (fold into deposits)

    event RouterCreated(
        address indexed validator, address router, address operator, uint256 commissionBps, uint256 buybackBps
    );
    event MaxCommissionSet(uint256 bps);
    event SwapperSet(address swapper);

    error CommissionTooHigh();

    constructor(address staking_, address owner_, uint256 maxCommissionBps_) {
        staking = staking_;
        _initializeOwner(owner_);
        maxCommissionBps = maxCommissionBps_;
    }

    /// @notice Bound future routers' commission (existing routers are immutable and unaffected).
    function setMaxCommission(uint256 bps) external onlyOwner {
        if (bps > 10_000) revert CommissionTooHigh();
        maxCommissionBps = bps;
        emit MaxCommissionSet(bps);
    }

    /// @notice Set the market buybacks execute on. Enable only once it has real liquidity and
    ///         manipulation protection — flush() swaps with no slippage bound.
    function setSwapper(address swapper_) external onlyOwner {
        swapper = swapper_;
        emit SwapperSet(swapper_);
    }

    function create(address validator, address operator, uint256 commissionBps, uint256 buybackBps)
        external
        returns (address router)
    {
        if (commissionBps > maxCommissionBps) revert CommissionTooHigh();
        bytes32 salt = keccak256(abi.encode(validator, operator, commissionBps, buybackBps));
        router = address(new FeeRouter{salt: salt}(validator, operator, staking, address(this), commissionBps, buybackBps));
        emit RouterCreated(validator, router, operator, commissionBps, buybackBps);
    }
}
