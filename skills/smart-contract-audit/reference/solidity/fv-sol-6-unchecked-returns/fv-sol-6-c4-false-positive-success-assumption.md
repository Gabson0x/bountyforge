# FV-SOL-6-C4 False Positive Success Assumption

## TLDR

The contract captures a failure signal from an external call but treats the failure path as a no-op, allowing execution to continue as if the call succeeded. This produces state inconsistencies and incorrect balance or permission assumptions when the external call actually failed.

## Detection Heuristics

**Empty Failure Branch**
- `if (!success) { }` or `if (!success) { /* ignored */ }` with no revert, emit, or corrective action
- `bool success = ext.doSomething(); if (!success) {}` pattern where the else path continues normally

**Suppressed Error with Continued Execution**
- Failure condition acknowledged in a comment but not acted upon: `// ignore failure`
- `try/catch` block with an empty `catch` body followed by state-altering code

**Incorrect Fallback Logic**
- Failure branch emits an event but does not revert, allowing the transaction to commit with partial state
- Failure branch logs an error off-chain (event) while on-chain state reflects success

## False Positives

- `require(success, "...")` enforces an immediate revert on the failure path
- Failure branch explicitly undoes prior state changes and reverts: `balance -= amount; revert(...)`
- Intentional degraded-mode logic where failure of the external call is a safe and documented operational outcome with correct state handling
