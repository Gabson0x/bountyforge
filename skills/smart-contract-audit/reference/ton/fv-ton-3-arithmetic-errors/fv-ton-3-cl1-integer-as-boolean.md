# FV-TON-3-CL1 Integer as Boolean

## TLDR

FunC represents true as `-1` (all bits set) and false as `0`. Code that stores `1` for true and uses bitwise NOT (`~`) to invert it produces `-2`, which is truthy - silently executing the branch that was intended for the false/inactive case.

## Detection Heuristics

**Non-canonical boolean storage**
- `int flag = 1;` or `load_uint(1)` returning `0`/`1` used directly in boolean logic with `~`
- `if (~ is_active)` where `is_active` may be `1` - `~1 == -2`, which is truthy, so the inactive branch always executes when `is_active = 1`
- Function returning `1` to indicate success, later called with `~ result` to check for failure

**Pattern requiring canonical normalization**
- `load_uint(1)` returns `0` or `1`; converting to FunC boolean requires `int b = -(cs~load_uint(1));` (negating maps `1 → -1`, `0 → 0`)
- Absence of this normalization before any `~`, `&`, or `|` operation on the loaded value

**Constants defined incorrectly**
- `const int TRUE = 1;` instead of `const int TRUE = -1;`
- Boolean return values from helper functions not annotated or reviewed for canonicality

## False Positives

- Variable is used only in `if (flag)` checks (truthy test) and never with `~` - non-canonical value is safe in this usage
- Value is `load_uint(1)` result used only with `== 0` or `== 1` comparisons, not with bitwise operators
