# FV-SOL-10-C4 Time Lags

## TLDR

Delaying block production or influencing the timing of oracle updates causes the price feed to serve stale data. Protocols that accept arbitrarily old prices expose themselves to exploitation using valuations that no longer reflect market reality - an attacker can front-run the staleness window to lock in favorable rates before a fresh update arrives.

## Detection Heuristics

**Stale Price Acceptance**
- `getLastUpdatedTime()` return value checked only for non-zero (`require(lastUpdated > 0)`), not for freshness relative to `block.timestamp`
- No `MAX_DELAY` constant or equivalent threshold defining the maximum acceptable age for oracle data
- `require(block.timestamp - lastUpdated <= MAX_DELAY)` absent from all price consumption paths
- `updatedAt` field from `latestRoundData()` fetched but the fetched value is unused or only logged

**Missing Heartbeat Enforcement**
- Protocol does not define a staleness tolerance per feed (different assets have different Chainlink heartbeats: 1 h, 24 h, etc.)
- No fallback behavior (pause, revert, or switch to backup oracle) triggered when a freshness check fails
- Price-dependent operations (liquidation, collateral valuation, swap) proceed regardless of how old the last update is

## False Positives

- `require(block.timestamp - lastUpdated <= MAX_DELAY)` enforced before every use of the price, with `MAX_DELAY` set to match or be tighter than the feed's documented heartbeat interval
- Protocol pauses or reverts all price-dependent operations and emits an event when the freshness check fails
- Push-based oracle with on-chain freshness proofs guarantees updates within a bounded window, removing the need for a consumer-side staleness check
