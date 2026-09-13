# FV-SOL-5-C2 Incorrect Conditionals

## TLDR

Results from conditions in if-else chains where more specific cases are tested after more general ones, making specific branches unreachable, or from wrong comparison operators that cause values to be handled by the wrong branch or skipped entirely.

## Detection Heuristics

**Unreachable Branches Due to Condition Order**
- A less restrictive condition (`balance > 100`) appears before a more restrictive one (`balance > 500`) in an if-else chain, making the latter dead code
- Any input satisfying the later condition also satisfies an earlier condition, so execution never reaches the later branch
- Multi-tier reward or fee logic where higher-value tiers are checked after lower-value tiers

**Wrong Comparison Operator**
- `>=` used where `>` is required, or vice versa, causing a reward or penalty to trigger one block too early or too late
- `block.number >= lastRewardBlock` instead of `block.number > lastRewardBlock` duplicates or skips a reward distribution
- `<` versus `<=` confusion at the boundary of a cooldown, vesting cliff, or lock period

**Boolean Logic Errors**
- `||` used where `&&` is required in a guard: `!isActive || isBlocked` passes when only one condition is true
- Negation applied to compound expression with wrong precedence: `!a && b` when `!(a && b)` was intended
- Double negation or tautological condition that always evaluates to true or false

## False Positives

- Most restrictive conditions checked first in descending threshold order
- Single comparison with no chained else-if - only one branch possible
- Coverage tests confirm all branches reachable with distinct input classes
