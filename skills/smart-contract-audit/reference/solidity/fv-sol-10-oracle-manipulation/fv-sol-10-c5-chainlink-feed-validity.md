# FV-SOL-10-C5 Chainlink Feed Validity Failures

## TLDR

`latestRoundData()` returns multiple fields that must all be validated. Missing any check leaves the protocol vulnerable to stale prices, deprecated feeds, and decimal scaling errors. Staleness means `updatedAt` is older than the feed's configured heartbeat - the feed stopped updating but continues returning the last known value. Round incompleteness means `answeredInRound < roundId` - the current round has not been answered and the returned price is from a prior round. Deprecated aggregator addresses can be replaced by Chainlink without notice, returning stale or zero values. Hardcoded decimal assumptions (e.g., always 8) fail for feeds that return 18 decimals, causing a 10^10 scaling error.

## Detection Heuristics

**Staleness Check Missing**
- `latestRoundData()` called but `require(updatedAt >= block.timestamp - MAX_STALENESS)` absent
- No per-feed maximum staleness constant defined - a single global timeout used for feeds with different heartbeats
- No fallback oracle or circuit breaker triggered when the staleness check fails

**Round Completeness Missing**
- `answeredInRound >= roundId` check absent from the validity suite
- `roundId` and `answeredInRound` destructured from `latestRoundData()` but neither is compared

**Deprecated Feed or Wrong Decimals**
- Aggregator address is `immutable` or a hardcoded constant with no governance update path
- `feed.decimals()` not called at runtime - value hardcoded as `8` or `18` in the price normalization formula
- Return value of `answer` cast to `uint256` and used directly without scaling to an internal precision (e.g., 1e18)

## False Positives

- All four checks present in every price consumption path: `answer > 0`, staleness against feed-specific heartbeat, `answeredInRound >= roundId`, and `feed.decimals()` called at runtime for normalization
- Aggregator address updatable via a timelock governance mechanism
- Secondary oracle deviation check acts as a circuit breaker, rejecting prices that diverge beyond a configured threshold even if individual validity checks pass
