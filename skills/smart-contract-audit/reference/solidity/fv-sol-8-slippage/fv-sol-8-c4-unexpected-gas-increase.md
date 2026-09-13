# FV-SOL-8-C4 Unexpected Gas Increase

## TLDR

When a swap wrapper forwards execution to an external DEX without a gas cap, an attacker or a malicious/upgraded DEX implementation can consume unbounded gas. This drives up transaction costs, can cause out-of-gas reverts for the user, or - in protocols that deduct gas costs from the output amount - constitutes a form of slippage that bypasses the stated minimum output check.

## Detection Heuristics

**Unbounded External Call**
- `dex.swap(tokenIn, tokenOut, amountIn)` called without a `{gas: N}` cap
- Low-level `address(dex).call(...)` without gas limit parameter
- No `gasleft()` check before or after the external call

**Missing Output Validation**
- Return value of `dex.swap(...)` not stored or not validated with `require(amountOut > 0)`
- `success` bool from low-level call not checked before decoding return data
- No minimum output enforced after the external call returns

**No Gas Cost Accounting**
- Protocol deducts fees or calculates net output after the swap without accounting for gas consumed by external call
- No refund mechanism when excess gas is consumed by an external DEX callback (e.g. `uniswapV3SwapCallback`)
- Flash loan callbacks or hook callbacks inside the DEX not considered in gas budget

## False Positives

- Gas costs are paid by the protocol treasury and are not deducted from the user's output amount
- Contract is a thin pass-through to a trusted, immutable router (e.g. Uniswap UniversalRouter) with known gas bounds
- Protocol uses a fixed-fee model where output calculation is independent of actual gas consumed
- MEV-protected relay handles gas optimization externally and the contract itself does not factor gas into output
