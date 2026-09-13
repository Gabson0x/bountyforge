# FV-SOL-10-C3 Manipulation Through External Markets

## TLDR

Oracles that aggregate prices from low-liquidity external markets (DEXes, AMMs) can be temporarily skewed within a single block or flash loan transaction. A protocol using such a price without smoothing or secondary validation executes collateral, liquidation, or swap logic at the manipulated value.

## Detection Heuristics

**Spot Price Oracle from DEX**
- Oracle call resolves to a DEX reserve ratio or AMM pool spot price (e.g., Uniswap `getReserves`, `slot0`) without a TWAP
- No block-level or time-weighted averaging applied before the price is consumed
- `collateral` or equivalent accounting value computed directly from a single `getPrice()` call with no smoothing
- Oracle interface accepts a `token` address argument and returns a single instantaneous value - classic sign of a spot-price aggregator

**No Flash-Loan or Single-Block Resistance**
- Price accepted within the same transaction as a swap or liquidity operation - no delay or snapshot mechanism
- No reentrancy guard or same-block protection on the price-consuming function
- No deviation check against a secondary non-AMM oracle (e.g., Chainlink) to reject manipulated spot readings
- `adjustCollateral` or equivalent function has no cooldown between calls

## False Positives

- Oracle source is Chainlink, Pyth, or another non-AMM feed that is not susceptible to single-block DEX manipulation
- Protocol uses a TWAP with a window of 30 minutes or longer, making single-block or flash-loan manipulation economically infeasible
- Deviation check against a secondary price source rejects outlier readings before they affect accounting
