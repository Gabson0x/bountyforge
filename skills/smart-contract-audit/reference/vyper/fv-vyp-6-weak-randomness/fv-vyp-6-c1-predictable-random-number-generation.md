# FV-VYP-6-C1 Predictable Random Number Generation

## TLDR

Vyper provides no native source of verifiable randomness. Contracts that derive randomness from `block.timestamp`, `blockhash`, `block.prevrandao`, or combinations thereof are vulnerable to manipulation by validators or to pre-computation by any on-chain observer. Vyper's lack of assembly makes some obfuscation techniques from Solidity unavailable, but the fundamental on-chain entropy problem is identical.

## Detection Heuristics

**Randomness derived solely from block variables**
- `block.timestamp % n` used to select a winner, determine an outcome, or assign a trait
- `convert(blockhash(block.number - 1), uint256) % n` used as a random index, where the block hash is known to the validator producing the block
- `block.prevrandao % n` used without any additional off-chain entropy, relying on a value the validator can influence by skipping a block

**`keccak256` of exclusively on-chain inputs**
- `keccak256(concat(convert(block.timestamp, bytes32), convert(msg.sender, bytes32)))` used to generate a random number, where both inputs are observable before transaction inclusion
- Seed updated with `keccak256(convert(self.random_seed, bytes32))` in a loop, providing only pseudorandomness without fresh external entropy

**Lottery or trait assignment in the same transaction as the triggering action**
- Winner drawn or NFT trait assigned in the same `draw_winner` or `mint` call that can be sandwiched or front-run by observing the mempool
- No commit-reveal scheme: participant submits entry and outcome is computed atomically in one transaction

**`blockhash` called with `block.number - 1` or a recent block**
- `blockhash(block.number - 1)` returns the previous block hash, which the current block's validator already knows
- `blockhash` with offsets greater than 256 blocks always returns `0x0`, silently collapsing entropy to a constant

## False Positives

- Contracts that use `block.prevrandao` in contexts where validator manipulation is economically irrational relative to the value at stake and no single validator controls enough stake to reliably bias the output
- Commit-reveal schemes where the reveal transaction uses a user-provided nonce combined with a hash committed in a prior block, preventing front-running of the outcome
- Contracts that integrate Chainlink VRF, Pyth Entropy, or another verifiable off-chain randomness oracle where the on-chain block variables are used only as a secondary, non-decisive input