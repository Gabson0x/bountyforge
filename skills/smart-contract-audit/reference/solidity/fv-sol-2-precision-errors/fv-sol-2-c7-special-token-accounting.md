# FV-SOL-2-C7 Special Token Accounting

## TLDR

Three related token behaviors break standard balance accounting assumptions: fee-on-transfer tokens deduct a fee during `transferFrom` so the contract records more than it received; rebasing tokens (stETH, AMPL, aTokens) change `balanceOf` over time without any transfer so cached balances go stale; and any contract that reads `balanceOf` once and stores it is vulnerable to drift from either mechanism or from direct token transfers. In all three cases the accounting variable diverges from actual holdings, enabling over-withdrawal, price manipulation, or stuck funds.

## Detection Heuristics

**Fee-on-Transfer**
- `balances[user] += amount` after `transferFrom(..., amount)` without a before/after balance check
- Protocol claims to support "any ERC20" or lists PAXG, STA, or other known deflationary tokens
- Share issuance formula `shares = amount * totalShares / totalAssets` - inflated numerator if `amount` exceeds actual receipt

**Rebasing Token**
- State variable (e.g., `totalAssets`, `_reserves`) accumulates deposit amounts for tokens like stETH, AMPL, or aTokens
- `totalAssets` or equivalent is updated only in protocol functions, not reflecting external rebase events
- Price or LTV calculation derived from stale accumulated value that diverges from live `balanceOf`

**Stale Cached Balance**
- `totalDeposited` or similar state variable never reconciled against live `token.balanceOf(address(this))`
- Protocol accepts direct `token.transfer(contract, x)` as a valid operation path, bypassing accounting
- Share price manipulable by donation: `balanceOf(this)` is higher than the internal tracking variable allows for

## False Positives

- Before/after balance delta used for all accounting: `received = balanceOf(after) - balanceOf(before)`
- Live `balanceOf(address(this))` is read in every view and price function rather than a cached state variable
- Wrapper tokens used: wstETH instead of stETH, eliminating rebasing exposure
- Token whitelist explicitly excludes fee-on-transfer and rebasing tokens with documented rationale
- Rebase is handled by a reconciliation function called atomically before any state-changing operation
