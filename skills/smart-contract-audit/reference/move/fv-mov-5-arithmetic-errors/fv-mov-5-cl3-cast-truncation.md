# FV-MOV-5-CL3: Narrowing Cast Truncation

## TLDR

Unlike standard arithmetic, Move's type casts (`value as u64`, `value as u8`) silently truncate high bits without aborting. A u128 value of `2^64 + 100` cast to u64 becomes `100`, bypassing amount checks. This is distinct from arithmetic overflow - Move aborts on arithmetic overflow but not on cast truncation.

## Detection Heuristics

- Search for `as u64`, `as u32`, `as u16`, `as u8` in financial calculations
- For each narrowing cast, trace the maximum value the source expression can hold - if it exceeds the target type's maximum, there is no abort, only silent truncation
- Verify an explicit bounds check precedes every narrowing cast: `assert!(value <= (U64_MAX as u128), EOverflow)`
- Financial calculations often use u128 intermediates for precision, then cast back to u64 for storage - these casts must be checked
- Double-scaling bugs (V139): if a value was already multiplied by a precision factor (1e18), casting or dividing to store may silently corrupt the result

## False Positives

- Bounds check present before the cast: `assert!(value <= MAX_U64)`
- Value is provably bounded by contract invariants (e.g., it was previously stored as u64 and only had u64-range operations applied)
- Cast on non-financial data (indices, flags) where truncation has no security implication
