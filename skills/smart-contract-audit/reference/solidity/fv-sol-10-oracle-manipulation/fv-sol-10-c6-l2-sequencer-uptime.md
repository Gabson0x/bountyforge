# FV-SOL-10-C6 L2 Sequencer Uptime Not Checked

## TLDR

On L2 networks (Arbitrum, Optimism, Base, and others), Chainlink price feeds continue to serve the last known price during sequencer downtime. When the sequencer resumes, there is a brief window where prices may be stale relative to L1 market moves. Protocols that use Chainlink feeds on L2 without querying the L2 Sequencer Uptime Feed may execute liquidations or trades at incorrect prices during or immediately after downtime.

## Detection Heuristics

**Missing Sequencer Uptime Check**
- Contract deployed on Arbitrum, Optimism, Base, or another L2 network that uses a centralized sequencer
- `latestRoundData()` called on a Chainlink price feed with no corresponding query to the L2 Sequencer Uptime Feed
- No `require(sequencerAnswer == 0)` guard (`0` means sequencer is up in Chainlink's uptime feed convention)
- `SEQUENCER_UPTIME_FEED` address absent from contract storage or constructor arguments

**Missing Grace Period After Restart**
- No `require(block.timestamp - startedAt >= GRACE_PERIOD)` enforced after verifying the sequencer is up
- `startedAt` from the uptime feed destructured but unused
- Liquidation, collateral valuation, or swap pricing executes immediately after sequencer restart without a cooldown

## False Positives

- Protocol deployed exclusively on Ethereum mainnet or another L1 with no sequencer
- Sequencer Uptime Feed queried with `answer == 0` check and a grace period enforced after `startedAt` before prices are consumed
- Protocol uses Pyth or Redstone with pull-based price updates that embed freshness proofs, bypassing sequencer-staleness issues
