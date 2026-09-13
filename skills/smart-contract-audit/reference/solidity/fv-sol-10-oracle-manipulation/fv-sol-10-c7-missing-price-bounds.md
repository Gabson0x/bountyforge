# FV-SOL-10-C7 Missing Oracle Price Bounds

## TLDR

An oracle can return a technically valid price - passing all staleness, round, and sign checks - that is wildly wrong for protocol purposes, such as during a flash crash or when a Chainlink circuit breaker activates. Without min/max sanity bounds or a secondary oracle deviation check, the protocol executes liquidations, swaps, or collateral valuations at that incorrect price. A related variant is a short TWAP window: a window under 30 minutes is manipulable by post-Merge validators who can hold a skewed AMM state across consecutive blocks they propose, shifting the TWAP at low cost.

## Detection Heuristics

**Missing Price Bounds**
- Oracle price used in liquidation, collateral valuation, or swap pricing without `require(price >= MIN_PRICE && price <= MAX_PRICE)`
- No deviation check against a secondary oracle source to detect outlier readings
- No heartbeat-rate or price-change-rate limiting (e.g., no maximum allowed per-update delta)
- `MIN_PRICE` and `MAX_PRICE` constants absent from the contract or set to `0` and `type(uint256).max` respectively

**Short TWAP Window**
- TWAP observation window configured to less than 30 minutes
- Post-Merge validator manipulation risk present: a validator controlling consecutive block proposals can hold a skewed AMM state across those blocks, slowly shifting the TWAP at low cost
- TWAP window length is a mutable parameter with no lower-bound governance constraint

## False Positives

- `require(price >= MIN_PRICE && price <= MAX_PRICE)` present in every price consumption path with bounds set to economically meaningful values
- Secondary oracle deviation check present with a reasonable threshold, rejecting any primary reading that diverges too far
- TWAP window is 30 minutes or longer and the window length is immutable or subject to a governance lower-bound
- Chainlink or Pyth used as the primary source rather than an AMM-derived spot or TWAP, eliminating the validator manipulation vector
