# FV-SOL-1-C1 Single Function

## TLDR

A single function performs an external call before updating its own state. An attacker's `receive` or `fallback` function re-enters the same function before the state change lands, allowing repeated withdrawal of the same balance within one transaction.

## Detection Heuristics

**CEI Violation in Withdrawal or Payout Functions**
- State variable (e.g., `balances[msg.sender]`) read for the transfer amount but not zeroed or decremented before `.call{value:}()`
- Pattern: `require(balances[x] > 0)` → `.call{value: balances[x]}("")` → `balances[x] = 0` (update after call)
- `.call{value:}("")` targeting `msg.sender` or any caller-controlled address before the corresponding accounting update

**External Call Vectors That Enable Callback**
- `.call{value:}("")` - forwards all remaining gas, allows arbitrary re-entry
- `payable(x).transfer()` or `.send()` - 2300-gas limit, but not a reliable guard post-Cancun
- Any low-level call to a user-supplied or caller-derived address before state is finalized

**Missing or Insufficient Guards**
- No `nonReentrant` modifier on functions that combine a balance read, an external call, and a state write
- Reentrancy guard stored in transient storage (`TSTORE`) without a fallback to regular storage for the 2300-gas path

## False Positives

- All accounting state is updated before the external call (CEI strictly followed)
- `nonReentrant` modifier (backed by regular storage) applied to the function
- `transfer()` or `send()` used and no `TSTORE` write is reachable within 2300 gas from any `receive`/`fallback` in scope
- Function is `view` or `pure` with no state-modifying side effects


