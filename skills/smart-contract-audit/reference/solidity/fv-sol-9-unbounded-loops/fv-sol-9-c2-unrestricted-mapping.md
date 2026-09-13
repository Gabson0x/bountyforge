# FV-SOL-9-C2 Unrestricted Mapping

## TLDR

Solidity mappings cannot be iterated natively, so developers often maintain a parallel array of keys. If this auxiliary array grows without restriction, any function that loops over it to aggregate or process mapping values will eventually exceed the block gas limit.

## Detection Heuristics

**Unbounded Key-Tracking Array**
- A storage `address[]` or `uint256[]` array is appended to inside a public or externally callable function with no length cap
- New keys are pushed when a mapping entry is first set, with no `require(arr.length < MAX)` guard
- The array is used as the iteration source for an on-chain aggregation or processing function

**Full-Array Iteration Without Pagination**
- `for (uint256 i = 0; i < users.length; i++)` iterates the key array inside a function called from a state-changing context
- No start/end range parameters allow callers to paginate the iteration
- Running total or aggregate is recomputed on every call rather than maintained incrementally

## False Positives

- Maximum key array length enforced unconditionally at insertion time
- Aggregation uses a precomputed running total updated at insertion rather than iterating at read time
- Iteration function accepts `start` and `end` parameters and callers are expected to chunk reads off-chain
- Array is populated only by a privileged role with a known, protocol-bounded upper size


