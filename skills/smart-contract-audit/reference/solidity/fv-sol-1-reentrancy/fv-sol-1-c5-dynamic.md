# FV-SOL-1-C5 Dynamic

## TLDR

Dynamic reentrancy arises when the target of an external call is a user-supplied parameter rather than a hardcoded or whitelist-verified address. Even with correct CEI ordering, the external call hands control to attacker-controlled code, which can re-enter the contract through a different entry point or exploit logic that was not covered by the reentrancy guard.

## Detection Heuristics

**User-Controlled External Call Target**
- Function signature `function f(address target, ...)` where `target` is used in a subsequent `.call{}`, `.delegatecall{}`, or token transfer without whitelist validation
- `target.call{value: amount}("")` where `target` is derived from `msg.sender`, `msg.data`, or any storage slot the caller can influence
- No `require(isApproved[target])` or equivalent allowlist check before the external call

**Reentrancy Through Side-Entry Points**
- The function deducts from a balance before the call but other functions in the same contract read that balance without a guard, enabling the callback to exploit sibling functions
- `nonReentrant` applied only to the function with the explicit guard, while the dynamically-called target can re-enter through an unprotected sibling

**Delegatecall With Dynamic Target**
- `address(target).delegatecall(data)` where `target` is caller-supplied - grants the target full write access to the contract's storage layout
- Proxy or router patterns that forward arbitrary `(target, calldata)` pairs from untrusted input

## False Positives

- State fully updated (all balances decremented, flags set) before the dynamic external call is issued
- `nonReentrant` applied to the function and all sibling functions that share the same state variables
- `target` validated against an immutable allowlist or registry before the call
- `delegatecall` restricted to a single implementation slot controlled by a time-locked admin
