# FV-SOL-1-C6 Read-Only

## TLDR

Read-only reentrancy occurs when a `view` function or an eligibility/price-check is called inside a state-modifying function after an external call. The view function returns stale or inconsistent state because the state update has not yet occurred, allowing a reentrant callback to pass checks it should fail or to read an artificially inflated or deflated value.

## Detection Heuristics

**View Function Called After External Call in the Same Transaction**
- Sequence: external call (e.g., ETH send) → callback re-enters → `view` function consulted before the state update in the original frame completes
- `getPrizeEligibility()`, `isEligible()`, `getPrice()`, `totalAssets()`, or any `view` that reads a state variable is callable from a reentrant callback while the original function's state update is pending
- Protocols that call an external price oracle or vault share-price function during a callback window where the pool's own state is transiently inconsistent

**Eligibility or Access Check Not Committed Before Interaction**
- `require(getPrizeEligibility())` or `require(balances[x] >= threshold)` evaluated, then an external call issued, then the flag or balance updated - the view check can be re-evaluated in a reentrant callback before the update lands
- `prizeClaimed`, `hasClaimed[user]`, or equivalent guard booleans set after the external call rather than before

**DeFi-Specific: Price or Share Manipulation via Read-Only Reentry**
- A DEX or lending protocol's `getPrice()`, `totalSupply()`, or `totalAssets()` read from a callback during a flash loan or liquidity removal, when pool reserves or vault balances are mid-update
- `lpToken.balanceOf(pool)` or `pool.getReserves()` called from a contract that receives the liquidity callback - returns values from an inconsistent intermediate state

## False Positives

- All guard flags and accounting state committed before the external call (`prizeClaimed = true` before `.call{value:}("")`)
- `nonReentrant` applied to both the state-modifying function and any function that the callback could re-enter to read stale state
- View function reads only immutable values or values that are not affected by the pending state update
- Protocol uses a TWAP or delayed oracle that is not susceptible to within-transaction state manipulation
