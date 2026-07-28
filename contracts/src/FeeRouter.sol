// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

interface INVNMStaking {
    function depositReward(address validator, uint256 amount) external;
    function rewardToken() external view returns (address);
    function totalStaked(address validator) external view returns (uint256);
}

/// @title FeeRouter
/// @notice Per-validator fee splitter. Set as the validator's fee recipient, it receives the
///         stablecoin fees paid out by the FeeManager's permissionless `distributeFees`;
///         `flush()` (also permissionless) pays the operator commission and deposits the
///         remainder into the staking pool for the validator's delegators.
contract FeeRouter {
    uint256 private constant BPS = 10_000;

    address public immutable validator; // delegation key in the staking contract
    address public immutable operator; // receives the commission
    address public immutable staking;
    address public immutable rewardToken;
    uint256 public immutable commissionBps;

    event Flushed(uint256 commission, uint256 deposited);

    error ZeroAddress();
    error InvalidBps();

    constructor(address validator_, address operator_, address staking_, uint256 commissionBps_) {
        if (validator_ == address(0) || operator_ == address(0) || staking_ == address(0)) revert ZeroAddress();
        if (commissionBps_ > BPS) revert InvalidBps();
        validator = validator_;
        operator = operator_;
        staking = staking_;
        rewardToken = INVNMStaking(staking_).rewardToken();
        commissionBps = commissionBps_;
    }

    /// @notice Split the router's reward-token balance: commission to the operator, rest to the
    ///         validator's stakers. No-op until the pool has stakers (balance is retained).
    function flush() external returns (uint256 deposited) {
        uint256 balance = SafeTransferLib.balanceOf(rewardToken, address(this));
        if (balance == 0 || INVNMStaking(staking).totalStaked(validator) == 0) return 0;
        uint256 commission = (balance * commissionBps) / BPS;
        if (commission != 0) SafeTransferLib.safeTransfer(rewardToken, operator, commission);
        deposited = balance - commission;
        if (deposited != 0) {
            SafeTransferLib.safeApprove(rewardToken, staking, deposited);
            INVNMStaking(staking).depositReward(validator, deposited);
        }
        emit Flushed(commission, deposited);
    }
}

/// @notice Deploys one deterministic FeeRouter per (validator, operator, commission).
contract FeeRouterFactory {
    address public immutable staking;

    event RouterCreated(address indexed validator, address router, address operator, uint256 commissionBps);

    constructor(address staking_) {
        staking = staking_;
    }

    function create(address validator, address operator, uint256 commissionBps) external returns (address router) {
        bytes32 salt = keccak256(abi.encode(validator, operator, commissionBps));
        router = address(new FeeRouter{salt: salt}(validator, operator, staking, commissionBps));
        emit RouterCreated(validator, router, operator, commissionBps);
    }
}
