# FV-SOL-2-C5 Time-Based

## TLDR

Contracts that use `block.timestamp` for fund release, access control, or randomness are exposed to two distinct risks: miner (or validator) manipulation of the timestamp by up to approximately 12-15 seconds per block, and the imprecision of treating a monotonically-increasing but not strictly-regular clock as a reliable scheduling mechanism. Lock periods enforced by exact timestamp comparisons can be bypassed or have their timing altered by block producers.

## Detection Heuristics

**Exact or Tight Timestamp Comparisons**
- `require(block.timestamp >= unlockTime)` where `unlockTime` was set as `block.timestamp + N` with small N (seconds to minutes)
- `if (block.timestamp == deadline)` - exact equality comparison against a stored timestamp
- Lock duration under 15 minutes where miner drift represents a non-trivial fraction of the intended window

**Timestamp as Unique Identifier or Seed**
- `block.timestamp` used as a seed for pseudo-randomness: `keccak256(abi.encode(block.timestamp, ...))`
- `block.timestamp` used as a unique nonce or ID in a mapping - two transactions in the same block share the same timestamp
- `tokenId = block.timestamp` or similar ID assignment

**Timestamp-Dependent Access Control**
- Function gated by `block.timestamp < startTime` where `startTime` is set by an admin in the same transaction as a critical action
- Vesting schedule or auction timing entirely controlled by stored timestamps without any block number cross-check
- `unlockTime` shared across all depositors (single state variable overwritten per deposit) allowing last-depositor to reset the lock

**Validator / Miner Manipulation Surface**
- Critical thresholds set within 30 seconds of block time granularity
- No buffer or grace period added to time-sensitive deadlines
- Protocol relies on timestamp for MEV-sensitive ordering (e.g., Dutch auction pricing)

## False Positives

- Time windows are measured in hours or days, making 15-second miner drift a negligible fraction of the intended duration
- Contract uses `block.number` instead of `block.timestamp` for sequencing logic
- Timestamp is used only for informational or logging purposes with no state-changing consequence
- Protocol explicitly documents and accepts the bounded imprecision of block timestamps for the given use case
