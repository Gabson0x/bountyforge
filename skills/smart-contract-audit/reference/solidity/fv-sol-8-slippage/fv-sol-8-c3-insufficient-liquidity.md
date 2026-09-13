# FV-SOL-8-C3 Insufficient Liquidity

## TLDR

When a DEX pool has insufficient liquidity relative to the swap size, price impact grows non-linearly and the resulting output can be drastically below fair value. Without a pre-swap liquidity check or a tightly enforced `amountOutMinimum`, the contract accepts any output the pool returns, including near-zero amounts caused by thin liquidity.

## Detection Heuristics

**No Pre-Swap Liquidity Validation**
- `dex.swap(tokenIn, tokenOut, amountIn)` called without checking available pool reserves
- No call to `getAvailableLiquidity()`, `getReserves()`, or equivalent before the swap
- Swap size not compared against pool depth as a percentage - no maximum trade-size-to-liquidity ratio enforced

**Insufficient Post-Swap Output Check**
- `require(amountOut > 0)` is the only output validation - accepts any non-zero dust amount
- `amountOutMinimum` absent or set to zero in the swap call
- No caller-supplied minimum output parameter; contract does not propagate slippage bound to the DEX router

**No Liquidity Threshold Parameter**
- Function signature lacks a `minLiquidity` or `minAmountOut` parameter
- Liquidity floor, if any, is hardcoded to zero or not present

## False Positives

- `amountOutMinimum` is a caller-supplied parameter validated on-chain by the router before execution
- Protocol enforces a minimum pool TVL threshold and reverts if liquidity falls below it before swapping
- Swap is routed across multiple pools with aggregate liquidity validation ensuring total output meets the user's minimum
- Concentrated liquidity pool (e.g. Uniswap v3) with tight price range guarantees sufficient depth at current tick
