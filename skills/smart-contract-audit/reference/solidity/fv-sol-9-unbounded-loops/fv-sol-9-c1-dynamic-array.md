# FV-SOL-9-C1 Dynamic Array

## TLDR

Loops that iterate over a dynamic array whose length grows with user-controlled input have unbounded gas cost. As the array grows, any function performing a full iteration will eventually exceed the block gas limit and revert permanently.

## Detection Heuristics

**Iteration Over User-Growable Array**
- `for (uint256 i = 0; i < arr.length; i++)` where `arr` is a storage array with no length cap
- Array is appended to by an externally callable function with no `require(arr.length < MAX)` guard
- No pagination or chunked access pattern for the iteration

**Missing Invariant on Array Bounds**
- No maximum length constant or state variable enforced at push time
- Array length depends on cumulative user calls rather than a protocol-controlled parameter

## False Positives

- Array length is bounded by a hard cap enforced on every push (`require(arr.length < MAX)`)
- Iteration occurs off-chain via a view function used only in scripts or subgraphs, never in a state-changing call chain
- Precomputed aggregate stored alongside the array so the full loop is never executed on-chain


