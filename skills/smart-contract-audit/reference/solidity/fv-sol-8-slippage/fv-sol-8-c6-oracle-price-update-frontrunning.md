# FV-SOL-8-C6 Oracle Price Update Front-Running

## TLDR

Push-model oracle integrations (Chainlink push, custom off-chain updater submitting to public mempool) expose the price update transaction before it lands. An attacker who sees a favorable update in the mempool can front-run it: open a position at the stale price, let the update land, then profit from the new price.

This is distinct from AMM price manipulation (FV-SOL-8-C1) - no flash loan is required. The attacker simply reads the public mempool and submits a transaction with a higher gas price.

## Detection Heuristics

**Push Oracle in Public Mempool**
- Protocol uses push-model oracle and `updatePrice()` submitted via public mempool
- Price is read in same block as update opportunity - no TWAP buffer
- No cooldown or circuit breaker between price update and position opening
- Pyth/Chainlink used in push mode without requiring price attestation in action tx
- Oracle updater uses `eth_sendRawTransaction` without a private relay

**Position Opening Against Stale Price**
- `oracle.latestAnswer()` or `oracle.getPrice()` called without verifying update recency
- No `require(updatedAt >= block.timestamp - maxStaleness)` freshness check
- Position sizing computed directly from the oracle value with no TWAP smoothing

## False Positives

- Pull-oracle: price attestation must be submitted atomically with the user action in the same tx (Pyth `updatePriceFeeds` pattern)
- TWAP of at least 30 minutes - single-block mempool visibility does not enable profitable front-run
- Private relay used for oracle update submissions (Flashbots Protect / MEV Blocker)
- Sequencer with private mempool (no public tx visibility before inclusion)
- Position size bounded - profit opportunity too small to cover gas cost of front-run
