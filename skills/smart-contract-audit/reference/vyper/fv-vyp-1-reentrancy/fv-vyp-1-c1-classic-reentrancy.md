# FV-VYP-1-C1 Classic Reentrancy

## TLDR

Classic reentrancy occurs when a Vyper contract performs an external call before updating its own state, allowing a malicious callee to re-enter the function and exploit the stale state. Vyper provides the `@nonreentrant` decorator as a built-in guard, but it must be applied explicitly and consistently.

## Detection Heuristics

**State updated after `raw_call`**
- `raw_call` invoked with `value=` parameter before the corresponding balance or state variable is zeroed or decremented
- Pattern: read balance into local variable, call external address, then set storage variable to zero
- ETH send via `raw_call(recipient, b"", value=amount)` where `amount` is derived from a storage variable not yet cleared

**Missing `@nonreentrant` decorator**
- `@external` functions that perform `raw_call`, interface calls, or send ETH lack a `@nonreentrant("lock")` decorator
- Multiple functions share access to the same balance mapping but not all carry the same `@nonreentrant` key

**Interface-based external calls before state writes**
- Calls through a Vyper interface (e.g., `IERC20(token).transfer(...)`) placed before storage mutations
- `self.balances[msg.sender]` or `self.shares[msg.sender]` read but not cleared before the outbound call

## False Positives

- `raw_call` with `revert_on_failure=False` used purely for logging or notification to a trusted internal address where re-entry has no exploitable state
- Functions decorated with `@nonreentrant` using a shared lock key that covers all co-dependent state mutations
- Contracts where all ETH transfers use the checks-effects-interactions pattern strictly: state fully updated before any outbound call