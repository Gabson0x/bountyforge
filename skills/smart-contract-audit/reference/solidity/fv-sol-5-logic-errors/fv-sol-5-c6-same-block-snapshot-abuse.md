# FV-SOL-5-C6 Same-Block Snapshot and Flash Loan Governance Abuse

## TLDR

Protocols that calculate yield, rewards, voting power, or insurance coverage based on a balance snapshot at a single point in time are vulnerable to flash loan amplification. An attacker borrows tokens, deposits before the snapshot (or in the same block), claims the benefit, then repays - all in one transaction. No minimum holding period means the capital requirement is zero.

## Detection Heuristics

- Governance voting uses `balanceOf` or current `balances[msg.sender]` rather than `getPastVotes(block.number - 1)`
- Reward/yield distribution uses current balance snapshot with no lock period
- Insurance or coverage calculated from `balanceOf` at claim time
- No minimum deposit age enforced before claiming rewards, votes, or benefits
- Deposit and withdraw in same block allowed - no cooldown between them
- Flash loan callbacks exist in the token contract and protocol is token-agnostic

## False Positives

- `getPastVotes(user, block.number - 1)` or equivalent past-block snapshot used
- Minimum holding period: `require(block.number > depositBlock[msg.sender] + N)`
- Reward accrual requires multiple blocks of staking - single-block stake earns nothing
- Protocol explicitly non-compatible with flash loanable tokens (whitelist enforced)
