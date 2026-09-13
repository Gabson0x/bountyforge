# FV-MOV-6-CL2: Supply Invariant Violations

## TLDR

Token/share supply must remain invariant: every mint has a corresponding deposit, every burn releases the corresponding asset. Violations include minting shares without receiving tokens, burning tokens without releasing collateral, and allowing self-transfers that trigger fee/reward snapshots without economic activity.

## Detection Heuristics

- Trace every call to mint functions - verify each requires a corresponding `Coin<T>` deposit of equal value
- Trace every burn - verify a `Coin<T>` withdrawal of proportional value is released to the user atomically
- Check whether `assert!(shares > 0)` is present after every share calculation - zero-share mints allow side-effect-only deposits
- Search for `transfer::transfer(coin, ctx.sender())` immediately after `balance::withdraw` - verify the withdrawn amount matches the shares redeemed
- Trace total supply update: every `mint` increments total supply; every `burn` decrements it; verify this happens in the same function, not in a separate step

## False Positives

- Mint/burn pair always executed atomically in the same function with amount validation
- Supply invariant assertion at end of deposit/withdrawal: `assert!(total_shares * share_price == total_assets)` (approximately)
- Zero-share check present: `assert!(shares > 0, EZeroShares)`
