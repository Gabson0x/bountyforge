# FV-SOL-6-C7 Zero-Amount Transfer Revert

## TLDR

Some non-standard ERC20 tokens (LEND, early BNB, and others) revert on `transfer(to, 0)` or `transferFrom(from, to, 0)`. Protocols that perform distribution loops or yield claims without guarding against zero amounts will be DoS'd when the distributed amount rounds to zero - permanently bricking claims for affected users or entire distribution rounds.

## Detection Heuristics

- `token.transfer(to, amount)` or `token.transferFrom(from, to, amount)` where `amount` can be zero
- Distribution loop: `share = total * weight[i] / totalWeight` - per-recipient share rounds to zero when `total` is small or `totalWeight` is large
- Unclaimed yield/fee accumulated over short periods with integer truncation
- No `if (amount > 0)` guard before transfer in claim/distribute functions
- Protocol documents support for tokens without specifying zero-transfer behavior

## False Positives

- `if (amount > 0)` guard before every transfer call in the hot path
- Minimum claim amount enforced: `require(claimable >= MIN_CLAIM)`
- Token whitelist explicitly verified to accept zero-amount transfers
- Pull-pattern where users claim non-zero amounts only (zero-balance claims reverted upstream)
