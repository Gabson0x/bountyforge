# FV-SOL-6-C5 Partial Execution with No Rollback

## TLDR

When an external call fails mid-function, prior state mutations already applied in the same transaction are not automatically rolled back unless the function reverts. Manual compensation logic is error-prone and may leave state partially modified, producing inconsistencies that compound over subsequent transactions.

## Detection Heuristics

**State Mutated Before External Call**
- `balance += amount` or mapping write followed by `externalContract.doAction()` where the call result may indicate failure
- Multiple sequential state changes before an external call, with only the last change manually reversed on failure

**Incomplete Manual Rollback**
- `if (!success) { balance -= amount; }` that reverses one change but ignores others made earlier in the function
- Manual compensation missing from one or more modified state variables
- Reentrancy risk: partial state visible to reentrant calls between the first mutation and the rollback

**Checks-Effects-Interactions Violation**
- External call placed before all state updates are finalized
- `require(success)` placed after multiple state changes rather than before them

## False Positives

- `require(success, "...")` causes the EVM to atomically revert all state changes in the transaction
- External call is made before any state mutation (checks-effects-interactions pattern fully followed)
- All state changes occur after the external call returns and are conditional on its success
