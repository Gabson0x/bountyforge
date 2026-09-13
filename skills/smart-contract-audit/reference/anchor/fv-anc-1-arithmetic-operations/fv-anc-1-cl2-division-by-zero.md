# FV-ANC-1-CL2 Division by Zero

## TLDR

Division by zero in an Anchor instruction causes a panic and transaction failure. When the divisor is derived from user-supplied input or an account field, an attacker can trigger a denial-of-service by passing zero.

## Detection Heuristics

**Unguarded Division**
- Expression `a / b` where `b` is read from `ctx.accounts`, instruction data, or a computed value without a prior zero-check
- Use of `%` (modulo) with a user-controlled divisor
- `.checked_div()` result ignored with `.unwrap()` rather than a proper error path

**Missing Zero Guard Before Division**
- No `require!(denominator != 0, ...)` or `if denominator == 0 { return Err(...) }` preceding the division
- Division inside helper functions that receive account data directly without sanitizing the divisor

**Indirect Zero Risk**
- Divisor derived from subtraction (`a - b`) where `b` could equal `a`, yielding zero as an intermediate
- Divisor comes from a freshly initialized account field whose default is zero

## False Positives

- Division by a compile-time constant that is non-zero
- Divisor is a protocol-defined base (e.g., a fixed decimal precision constant like `1_000_000`) that is never settable by users
