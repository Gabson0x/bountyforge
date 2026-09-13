# FV-SOL-5-C11 Weak On-Chain Randomness

## TLDR

Randomness derived from on-chain values is manipulable by validators/miners or predictable by any caller, making it unsuitable for games, lotteries, NFT trait generation, or any outcome where a participant can gain an advantage by knowing the result in advance.

- `block.prevrandao` (formerly `block.difficulty`): validator-influenceable on PoS - validators can choose to reveal or withhold their block proposal to get a favorable value
- `blockhash(block.number - 1)`: visible to the tx sender before inclusion; miners could reorder
- `block.timestamp`, `block.coinbase`: influenceable by block proposer

A commit-reveal scheme provides genuine randomness only when the reveal is bound to a future block hash and there is slashing/penalty for non-reveal.

## Detection Heuristics

- `block.prevrandao`, `block.difficulty`, `block.timestamp`, `block.coinbase`, or `blockhash` used as primary randomness source
- Any combination of the above: `keccak256(abi.encodePacked(block.timestamp, msg.sender))` is still manipulable
- Commit-reveal without future-block reveal: reveal uses current block hash
- Commit-reveal with no penalty for non-reveal: validator reveals only favorable outcomes
- `uint256(keccak256(...)) % N` for lottery, rare NFT, or game outcome

## False Positives

- Chainlink VRF v2+ with minimum 3-block confirmation delay
- Commit-reveal with verifiably future block hash and economic penalty (slashing) for non-reveal
- Outcome has no economic value - randomness manipulation unprofitable
- Off-chain randomness with on-chain verification (e.g., DRAND, VDF proof)
