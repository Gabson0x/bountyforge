# FV-TON-3-CL2 Signed Unsigned Integer Confusion

## TLDR

`load_int()` can return negative values; using it for amounts, balances, or sizes that must be non-negative allows a caller to supply a negative value that bypasses positive-amount checks and causes incorrect arithmetic.

## Detection Heuristics

**load_int used for financial amounts**
- `int amount = in_msg_body~load_int(256);` for a transfer or deposit amount - negative amounts can pass `amount > 0` checks if the comparison is done before the signedness is noticed
- `int size = cs~load_int(32);` used as a loop bound or allocation size

**Missing range validation after load**
- No `throw_unless(error::invalid_amount, amount > 0)` or `throw_unless(error::invalid_amount, amount >= MIN_AMOUNT)` after loading
- No upper bound check - extremely large values can cause downstream overflow

**store_uint width mismatch**
- Value computed as signed 257-bit integer then packed with `store_uint(amount, 64)` - if `amount > 2^63`, it silently truncates
- Storing a 120-bit coins value in a 64-bit field via `store_uint` loses the high bits; `store_coins` uses variable-length encoding and avoids this

## False Positives

- `load_int` used for a field that is genuinely signed by protocol design (e.g., a signed delta) with subsequent sign-aware arithmetic
- Truncation is safe because the protocol enforces an invariant upstream that the value fits in the target width
