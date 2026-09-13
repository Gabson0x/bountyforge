# FV-SOL-5-C1 Boundary Misalignment

## TLDR

Occurs when code fails to correctly define exclusive versus inclusive boundaries at interval thresholds, causing values at the cutoff to fall into the wrong range, be double-counted, or be skipped entirely.

## Detection Heuristics

**Mixed Inclusive/Exclusive Operators in Chained Conditions**
- Adjacent if-else ranges mix `<` and `<=` without accounting for overlap at shared boundary values
- A value satisfies two consecutive conditions simultaneously (e.g., `score == 100` matches both `score <= 100` and `score < 150` if the chain is written incorrectly)
- Boundary constant appears on both sides of adjacent range checks without mutual exclusion

**Off-by-One in Loops and Epoch Windows**
- Loop bound written as `i <= arr.length` instead of `i < arr.length`
- Time window start or end expressed as `block.timestamp >= windowEnd` when `>` is required to exclude the boundary
- Epoch or slot number checked with `>=` at both lower and upper bound of adjacent tiers

**Tiered Threshold Logic**
- Token amount or score thresholds use inconsistent operators across tiers
- A tier boundary value is reachable by two different branches due to operator mismatch
- Hardcoded boundary constants differ between the condition and the documented specification

## False Positives

- Each range uses explicit `>= lower && < upper` with no overlap between adjacent conditions
- Boundary constants defined once and reused consistently across all comparison sites
- Unit tests cover exact boundary values and confirm each lands in exactly one branch
