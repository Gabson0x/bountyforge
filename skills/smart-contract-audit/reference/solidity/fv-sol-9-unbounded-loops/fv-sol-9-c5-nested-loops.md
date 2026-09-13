# FV-SOL-9-C5 Nested Loops

## TLDR

Nested loops whose bounds are both determined by user-controlled data produce O(n*m) gas costs. Even modest growth in either dimension can push the combined iteration count past the block gas limit, permanently bricking any function that relies on full traversal in a single transaction.

## Detection Heuristics

**Double-Dimension User-Controlled Iteration**
- Outer loop iterates over a user-supplied or user-growable array of addresses or IDs
- Inner loop iterates over a per-user storage array (e.g., `mapping(address => uint256[])`) with no bounded length
- Neither loop dimension has a hard cap enforced at insertion time

**Quadratic or Superlinear Gas Growth**
- Gas cost scales as O(n * m) where both n and m grow with user input
- No precomputed aggregate eliminates the inner loop at read time
- Function is called in a state-changing context, not exclusively off-chain

**Multiple Levels of Nesting**
- More than two nested loops present in a single function
- Each level iterates over a different user-contributed collection
- Aggregate or total recomputed on every invocation rather than updated incrementally

## False Positives

- Inner loop iterates over a fixed-size array bounded by a protocol constant
- Precomputed per-user totals stored in a mapping eliminate the inner loop at read time
- Function is a `view` used exclusively off-chain and never in the call chain of a state-changing transaction
- Both array dimensions are bounded by hard caps enforced unconditionally at insertion


