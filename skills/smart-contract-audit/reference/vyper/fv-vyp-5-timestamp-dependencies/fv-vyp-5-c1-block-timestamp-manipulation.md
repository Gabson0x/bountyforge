# FV-VYP-5-C1 Block Timestamp Manipulation

## TLDR

`block.timestamp` in Vyper exposes the same miner-manipulable value as Solidity. Validators (post-Merge) can adjust the timestamp within the protocol's allowed drift to influence time-dependent logic such as auction deadlines, vesting cliffs, or cooldown periods. Short time windows measured in seconds are especially susceptible.

## Detection Heuristics

**Critical state transitions gated on exact `block.timestamp` comparison**
- `assert block.timestamp >= self.unlock_time` or `assert block.timestamp < self.deadline` where the window is seconds-wide and the outcome has financial value
- Auction end or sale close logic using `block.timestamp == self.end_time` (exact equality) rather than a range check
- Cooldown logic computing `block.timestamp - self.last_action[msg.sender] < COOLDOWN` where COOLDOWN is a small constant (under 30 seconds)

**`block.timestamp` used as a seed or entropy source**
- `convert(block.timestamp, bytes32)` passed to `keccak256` as the sole or primary entropy input for randomness
- Winner or outcome selection using `block.timestamp % n` where `n` determines a prize

**Timestamp-based vesting or unlock with validator-influenceable precision**
- `self.vesting_end = block.timestamp + duration` set at deployment where `duration` is measured in seconds and the initial timestamp can be nudged by the block proposer
- Staking reward calculations using `block.timestamp - self.stake_start` where a small timestamp delta meaningfully changes the reward amount

**`block.number` used as a timestamp proxy with inaccurate block-time assumptions**
- Comments or constants assume exactly 12-second block times: `BLOCKS_PER_HOUR: constant(uint256) = 300` when actual block times vary
- Duration in blocks derived from `seconds / 12` hardcoded without accounting for missed slots or Ethereum consensus changes

## False Positives

- Time windows measured in hours or days where the allowed validator drift (a few seconds to ~15 seconds) is economically insignificant relative to the stakes
- `block.timestamp` used only for informational event logging without affecting control flow or fund distribution
- Contracts on chains with deterministic block timestamps (e.g., certain L2s with fixed sequencer timing) where manipulation is not possible within the threat model