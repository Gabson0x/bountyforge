# FV-SOL-9-C3 Recursive Calls

## TLDR

Solidity imposes a call-stack depth limit of 1024 frames. Recursive self-calls or chains of delegating function calls that scale with user-supplied input will exhaust the call stack or gas budget before completing. Even when disguised as iterative withdrawal logic, each self-call consumes additional stack frames and per-call gas overhead that grows linearly with the input value.

## Detection Heuristics

**Direct Self-Recursive Call**
- A `public` or `external` function calls itself with a decremented counter or shrinking parameter
- No base case enforces an early return before call-stack exhaustion
- Each recursive frame performs an external interaction (transfer, call) multiplying gas consumption

**Indirect Recursion via External Call Cycle**
- Function A calls function B which calls back into function A within the same transaction
- No reentrancy guard prevents the cycle
- Depth scales with a user-controlled amount or count parameter

**Linear Work Per Unit of User-Supplied Input**
- Gas cost is O(n) where n is a user-supplied numeric argument (e.g., processing 1 unit per recursive frame)
- No upper bound enforced on the argument at function entry
- A loop with the same logic would be equally unbounded

## False Positives

- Recursion depth is strictly bounded by a protocol-controlled constant, not user input
- `nonReentrant` modifier is present and prevents callback cycles
- Operation is restructured to a single bulk transfer rather than one-unit-at-a-time calls


