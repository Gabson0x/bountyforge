# FV-ANC-3-CL11 No Reload After Account Mutation

## TLDR

In Anchor, after mutating an account via a `load_mut()` or direct field write, subsequent reads of the same account may use a stale in-memory copy. Without explicitly reloading, the program may act on outdated state, leading to logic errors when the mutation affects values read later in the same instruction.

## Detection Heuristics

**load_mut Scope Not Dropped Before Subsequent load**
- `let mut data = ctx.accounts.account.load_mut()?` followed by logic that reads `ctx.accounts.account` without dropping the mutable borrow and calling `.reload()` or `.load()`
- Borrow of mutable account data not scoped tightly, causing stale in-memory values to persist beyond the mutation

**Mutation Followed by Computation Using Pre-Mutation Values**
- Account field updated (e.g., `account.balance = new_balance`) and then used in a subsequent calculation that should reflect the updated value, but the local variable still holds the old value
- CPI invoked after mutation that passes the account, but the caller reads the account's fields again after the CPI without reloading

**Missing .reload() After CPI**
- After a CPI that mutates an account owned by the current program, the instruction reads the account's fields without calling `.reload()` to pull the updated data from the account's storage

## False Positives

- Mutation and subsequent reads are in separate instructions; Anchor re-deserializes on each instruction entry
- Account is written exactly once at the end of the instruction and no further reads occur after the write
