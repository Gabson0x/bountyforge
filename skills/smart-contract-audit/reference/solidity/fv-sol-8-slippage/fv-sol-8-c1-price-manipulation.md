# FV-SOL-8-C1 Price Manipulation

## TLDR

Relying solely on a DEX's own spot price to validate or derive swap parameters allows an attacker to manipulate the pool state (via flash loan or large trade) immediately before the victim transaction, causing extreme slippage. Without cross-referencing an external or time-weighted price, the contract has no means to detect that the in-block price is artificially distorted.

## Detection Heuristics

**Single On-Chain Price Source**
- `dex.getPrice(tokenIn, tokenOut)` used as sole price reference with no secondary validation
- Spot price read and swap executed in the same transaction without a deviation check
- No TWAP oracle reference; no Chainlink or Pyth feed comparison before swap

**Missing Output Validation**
- `amountOut` not checked against a caller-supplied or oracle-derived minimum
- `require(amountOut > 0)` is the only post-swap guard - accepts any non-zero output
- `amountOutMinimum` absent from swap call parameters

**No Deviation Bound**
- No `maxSlippagePercent` or equivalent parameter accepted from caller
- No `require` that spot price is within N% of reference price before proceeding with swap

## False Positives

- Price is validated against a TWAP of at least 10 minutes before the swap executes
- Deviation check is enforced between DEX spot price and a Chainlink or Pyth reference feed
- `amountOutMinimum` is a caller-supplied parameter validated on-chain by the router


