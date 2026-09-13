# FV-SOL-5-C3 Improper State Transitions

## TLDR

A contract with a defined lifecycle (e.g., NotStarted, Active, Paused, Completed) allows state-modifying functions to execute without validating the current state, permitting out-of-order or repeated transitions that violate invariants and can be exploited.

## Detection Heuristics

**Missing Predecessor State Guard**
- A transition function modifies `state` without a `require(state == ExpectedPredecessor)` guard
- Terminal state (e.g., `Completed`, `Cancelled`) reachable directly from any state, not only from the valid predecessor
- Function that advances lifecycle phase contains no state check at all

**Multiple Entry Points Without Mutual Exclusion**
- Two or more functions can set the contract to the same state without checking for conflicts
- Re-entrancy or repeated calls to an initializer move state backward or cycle it
- `pause()` and `resume()` functions do not verify opposing states before toggling

**Missing State Validation on Operational Functions**
- Functions that should only execute in a specific phase (e.g., `claimReward` only during `Active`) lack a phase guard
- Withdrawal, reward distribution, or settlement callable before the contract reaches the required state
- State variable used as a flag is set but never checked by dependent functions

## False Positives

- Every transition function has an explicit `require(state == PreviousState)` check
- Only one valid predecessor state is permitted for each target state
- State machine transitions are documented and tested with invalid-sequence inputs that confirm reversion
