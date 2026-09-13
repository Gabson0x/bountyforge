# FV-SOL-6-C3 Silent Fail

## TLDR

A function call fails without detection and execution continues as if it succeeded, producing an invalid or inconsistent contract state. This pattern arises whenever a callee signals failure through a return value rather than a revert and the caller does not inspect that value.

## Detection Heuristics

**Bool-Returning External Calls Without Checks**
- External function typed `returns (bool)` called as a statement with the return discarded
- `externalContract.performAction()` where `performAction` returns `bool` but the caller does not capture it

**State Updated After Unchecked Call**
- Contract state (mappings, balances, counters) updated immediately after a call whose success was not verified
- Event emitted signaling completion before the success condition is confirmed

**Interface Mismatch**
- Interface declares `returns (bool)` but the implementing contract may return `false` on failure rather than reverting
- Protocol mixes reverting and non-reverting callee contracts under the same interface without differentiating handling

## False Positives

- Return value is captured and `require(success, "...")` is present before any state mutation
- Callee contract is verified to always revert on failure and never returns `false` (documented and tested)
- Function is a view/pure call with no state impact where the result is intentionally unused
