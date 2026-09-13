# FV-SOL-5-C8 Force ETH Injection

## TLDR

Three mechanisms send ETH to a contract without triggering `receive()` or `fallback()`:

1. **selfdestruct**: forced ETH transfer to any address, no code execution
2. **Coinbase / block reward**: mining/validating awards ETH directly to `block.coinbase`
3. **CREATE2 pre-funding**: sending ETH to a deterministic address before the contract is deployed

Contracts that use `address(this).balance` for invariant checks, exact-match accounting, or as a trigger condition can have those invariants violated by any of these mechanisms.

## Detection Heuristics

- `require(address(this).balance == X)` or `require(address(this).balance >= X)` as invariant guard
- `require(address(this).balance == 0)` as initialization guard
- ETH accounting that adds only through `receive()`/`fallback()` without reconciliation against `address(this).balance`
- Token price derived from `address(this).balance` without an internal accounting variable

## False Positives

- Internal accounting only: `totalDeposits` state variable updated in all ETH-receiving paths
- Contract explicitly designed to accept arbitrary ETH (e.g., ETH wrapper, donation contract)
- `address(this).balance` read only for informational/view purposes with no state side-effect
- selfdestruct target protection not required for non-critical ETH flows (documented)
