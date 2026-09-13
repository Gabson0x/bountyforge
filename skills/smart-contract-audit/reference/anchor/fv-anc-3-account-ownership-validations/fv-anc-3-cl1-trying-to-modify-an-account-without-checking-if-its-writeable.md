# FV-ANC-3-CL1 Trying to Modify an Account Without Checking if it is Writable

## TLDR

Solana requires accounts to be marked writable in the transaction's account list before the runtime permits lamport or data changes. Writing to an account not flagged as writable will either panic or silently fail depending on the Solana version, and opens logic errors when the writability check is absent at the program level.

## Detection Heuristics

**Mutation Without Writable Guard**
- `ctx.accounts.config.data.borrow_mut()` or similar data mutation on an `AccountInfo` without a prior `require!(ctx.accounts.config.is_writable, ...)` check
- Lamport arithmetic on an account (e.g., `**account.lamports.borrow_mut() += ...`) without verifying `is_writable`

**Missing mut Constraint in Anchor Context**
- Account field in `#[derive(Accounts)]` struct lacks `#[account(mut)]` yet the instruction body writes to it
- Anchor `Account<'info, T>` used without `mut` constraint on a data-mutating instruction

**Unconditional Write on User-Supplied Accounts**
- `AccountInfo` received from `ctx.remaining_accounts` or a raw account list is written without checking `is_writable`

## False Positives

- Account is written only via CPI and the callee program enforces writable constraints on its own accounts
- Read-only deserialization of account data into a local variable without any mutation of the account itself
