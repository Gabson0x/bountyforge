# FV-MOV-5-CL1: Bitwise Overflow and Custom Math Library Errors

## TLDR

Move checks standard arithmetic overflow and aborts, but bitwise left-shift (`<<`) is NOT checked - it silently overflows. This vector directly caused the Cetus $223M exploit: a `checked_shlw` function had an incorrect shift limit (256 instead of 192), allowing the shift to overflow and produce a near-zero price, enabling unlimited drain.

## Detection Heuristics

- Search for `<<` operators in all financial or pricing calculations - any left-shift without an explicit `assert!(shift <= safe_max_shift)` is a finding
- For u64 math: maximum safe left shift is 63; for u128: 127; for u256: 255 - any comparison to a higher or miscalculated value is exploitable
- Audit custom math libraries (fixed-point, sqrt, concentrated liquidity math) for boundary inputs: very small amounts, near-MAX values, zero inputs
- Verify custom library functions are tested with fuzz inputs at `u64::MAX`, `0`, `1`, and values near the maximum safe shift
- Double-check any function named `checked_shl*`, `safe_shift`, or similar - the "checked" name may give false confidence

## False Positives

- Explicit overflow check present before every shift: `assert!(shift < TYPE_BITS)` or equivalent
- Bitwise operations on non-financial data (flags, bitmasks) where overflow is not exploitable
- Well-audited external library used with verified correct bounds
