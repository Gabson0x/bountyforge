# FV-SOL-2-C1 Token Decimals

## TLDR

Precision errors occur when contracts hardcode a decimal assumption (commonly 18) rather than reading the token's actual `decimals()` value. When a contract interacts with tokens like USDC (6 decimals) or WBTC (8 decimals) using an 18-decimal assumption, amounts are over- or under-scaled by orders of magnitude, leading to catastrophically incorrect transfers or balance accounting.

## Detection Heuristics

**Hardcoded Decimal Scaling**
- `amount * 10**18` or `amount * 1e18` in a function that accepts an arbitrary ERC20 address
- `amount / 10**18` used to normalize values without consulting `token.decimals()`
- Constant like `uint256 constant PRECISION = 1e18` applied uniformly across tokens with different decimals

**Missing Decimal Query**
- No call to `token.decimals()` anywhere in the contract or its libraries
- Conversion between token amounts and internal units does not factor in per-token decimal count
- Multi-token contracts (e.g., AMMs, lending pools) that normalize all token values with the same fixed exponent

**Cross-Token Comparison Without Normalization**
- Two token balances compared or combined directly without adjusting for differing `decimals()` values
- Price or rate computed as `tokenA.balanceOf(...) / tokenB.balanceOf(...)` where decimals differ
- Oracle price feed combined with a raw token amount without decimal reconciliation

## False Positives

- Contract explicitly documents and enforces that only 18-decimal tokens are accepted, enforced at the token whitelist or constructor level
- `decimals()` is called dynamically per token and the result is used in every scaling operation
- Protocol normalizes all values to a fixed internal precision (e.g., 18 decimals) at ingestion time, with the normalization factor derived from `token.decimals()` on each token


