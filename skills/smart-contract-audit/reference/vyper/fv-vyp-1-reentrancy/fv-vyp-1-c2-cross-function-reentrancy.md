# FV-VYP-1-C2 Cross-Function Reentrancy

## TLDR

Cross-function reentrancy occurs when an external call in one function allows a re-entrant attacker to invoke a different function in the same contract while shared state is still inconsistent. Vyper's `@nonreentrant` decorator prevents this only when the same lock key is applied to every function that reads or writes the shared state.

## Detection Heuristics

**Inconsistent `@nonreentrant` key coverage**
- Function A performs an outbound call and carries `@nonreentrant("lock")`, but function B that mutates the same storage mapping does not
- Two functions operate on the same `HashMap` (e.g., `balances`, `shares`) with different or absent `@nonreentrant` keys
- A `transfer` or `approve`-style function modifies the same state as a `withdraw` function but lacks a matching guard

**Stale state exploitable via sibling function during outbound call**
- `raw_call` or interface call to an untrusted address before `self.balances[msg.sender]` is zeroed, while a sibling `transfer` function still reads that mapping
- Contract sends ETH in function A, and function B allows spending or transferring the same balance without checking the in-flight amount

**Manual mutex patterns with incomplete coverage**
- `locked: HashMap[address, bool]` guard set and cleared within one function but absent from related functions that access the same balances
- Lock variable stored per-user (`locked[msg.sender]`) rather than globally, allowing a different account to be used as re-entry vector

## False Positives

- Contracts where every function touching shared state carries the same `@nonreentrant` key, providing mutual exclusion across all entry points
- Read-only (`@view`) sibling functions that do not modify state and cannot affect the outcome of an in-progress withdrawal
- Trusted internal calls between functions on the same contract instance where no external code executes between the state read and write