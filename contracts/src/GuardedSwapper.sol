// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ISwapper } from "./FeeRouter.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/// @title GuardedSwapper
/// @notice The production-shaped `ISwapper` for fee buybacks: wraps an inner market for one
///         fixed (tokenIn → tokenOut) pair and enforces a per-swap size cap plus a minimum
///         execution price anchored to an EMA of past swaps. A sandwiched or manipulated pool
///         makes the swap revert instead of donating the buyback — routers hold funds and retry.
/// @dev `owner` (the Safe) seeds the reference price and tunes the guards. This is what the
///      FeeRouterFactory's `swapper` should point at; the inner market stays swappable.
contract GuardedSwapper is Ownable, ISwapper {
    uint256 private constant BPS = 10_000;
    uint256 private constant WAD = 1e18;

    address public immutable tokenIn; // fee stablecoin
    address public immutable tokenOut; // NVNM

    address public inner; // the actual market
    uint256 public maxAmountIn; // per-swap size cap
    uint256 public maxDeviationBps; // allowed drop below the EMA execution price
    uint256 public emaAlphaBps; // EMA weight of the newest observation
    uint256 public emaPrice; // tokenOut per WAD tokenIn; 0 until seeded

    event GuardsSet(
        address inner, uint256 maxAmountIn, uint256 maxDeviationBps, uint256 emaAlphaBps
    );
    event PriceSeeded(uint256 price);
    event GuardedSwap(uint256 amountIn, uint256 amountOut, uint256 price, uint256 emaPrice);

    error WrongPair();
    error NotSeeded();
    error InvalidBps();
    error ZeroAmount();
    error AmountTooLarge();
    error PriceBelowFloor();

    constructor(address owner_, address tokenIn_, address tokenOut_) {
        _initializeOwner(owner_);
        tokenIn = tokenIn_;
        tokenOut = tokenOut_;
    }

    function setGuards(
        address inner_,
        uint256 maxAmountIn_,
        uint256 maxDeviationBps_,
        uint256 emaAlphaBps_
    ) external onlyOwner {
        if (maxDeviationBps_ > BPS || emaAlphaBps_ > BPS) {
            revert InvalidBps();
        }
        inner = inner_;
        maxAmountIn = maxAmountIn_;
        maxDeviationBps = maxDeviationBps_;
        emaAlphaBps = emaAlphaBps_;
        emit GuardsSet(inner_, maxAmountIn_, maxDeviationBps_, emaAlphaBps_);
    }

    /// @notice Seed or reset the reference price (tokenOut per 1e18 tokenIn).
    function seedPrice(uint256 price) external onlyOwner {
        emaPrice = price;
        emit PriceSeeded(price);
    }

    function swap(address tokenIn_, address tokenOut_, uint256 amountIn, uint256 minOut)
        external
        returns (uint256 out)
    {
        if (tokenIn_ != tokenIn || tokenOut_ != tokenOut) revert WrongPair();
        uint256 ema = emaPrice;
        if (inner == address(0) || ema == 0) revert NotSeeded();
        if (amountIn == 0) revert ZeroAmount();
        if (amountIn > maxAmountIn) revert AmountTooLarge();

        SafeTransferLib.safeTransferFrom(tokenIn, msg.sender, address(this), amountIn);
        SafeTransferLib.safeApproveWithRetry(tokenIn, inner, amountIn);
        out = ISwapper(inner).swap(tokenIn, tokenOut, amountIn, minOut);

        uint256 price = (out * WAD) / amountIn;
        if (price < (ema * (BPS - maxDeviationBps)) / BPS) revert PriceBelowFloor();
        emaPrice = (price * emaAlphaBps + ema * (BPS - emaAlphaBps)) / BPS;
        SafeTransferLib.safeTransfer(tokenOut, msg.sender, out);
        emit GuardedSwap(amountIn, out, price, emaPrice);
    }
}
