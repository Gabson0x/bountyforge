# FV-ANC-1-CL1 Overflow/Underflow in Arithmetic Operations

## TLDR

Integer overflow and underflow in Rust Anchor programs occur when arithmetic on u64/u128/i64 values wraps or panics, leading to corrupted balances, bypassed caps, or exploitable logic. In release builds, Rust integers wrap silently unless checked variants are used.

## Detection Heuristics

**Unchecked Arithmetic on Account Fields**
- Direct use of `+`, `-`, `*` operators on account field values such as `ctx.accounts.user.balance + amount`
- Arithmetic result assigned directly without `.checked_add()`, `.checked_sub()`, `.checked_mul()`, or `.checked_div()`
- Use of `as` casts (e.g., `u128 as u64`) that silently truncate

**Saturating or Wrapping Instead of Checked**
- Use of `.saturating_add()` or `.wrapping_add()` in financial or security-sensitive contexts where saturation masks real overflow
- Intermediate values computed in u64 that could exceed u64::MAX before being cast

**Absence of Error Propagation on Arithmetic**
- `.unwrap()` on checked arithmetic instead of `.ok_or(ErrorCode::...)` or `?`
- Arithmetic inside a loop over account balances without per-iteration overflow checks

## False Positives

- Arithmetic on values bounded by protocol invariants already enforced earlier in the instruction, making overflow mathematically impossible
- Use of `.saturating_add()` on non-financial counters such as event sequence numbers where saturation is the intended behavior
- Arithmetic inside `#[cfg(test)]` blocks that only appear in test code
