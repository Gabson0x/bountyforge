# FV-ANC-3-CL2 Trying to Access Account Data Without Ownership Checks

## TLDR

On Solana, any account can be passed to a program. Without verifying that an account is owned by the expected program, an attacker can substitute a look-alike account controlled by a different program, causing the instruction to operate on attacker-crafted data.

## Detection Heuristics

**Raw Data Borrow Without Owner Verification**
- `ctx.accounts.config.data.borrow()` on an `AccountInfo` or `UncheckedAccount` without checking `ctx.accounts.config.owner`
- `try_from_slice` or manual deserialization of account data without a preceding owner check

**Missing owner Constraint in Anchor Context**
- `UncheckedAccount<'info>` used to read structured data without `#[account(owner = expected_program_id)]` constraint
- `AccountInfo` interpreted as a known struct type without verifying `account.owner == &expected_program::ID`

**Ownership Checked Against Wrong Program**
- `account.owner == ctx.program_id` check missing, or checked against system program when the data account should be owned by the current program

## False Positives

- Anchor `Account<'info, T>` type used, which automatically enforces program ownership during deserialization
- Account is the System Program, Token Program, or another well-known program account where ownership of the program itself is not meaningful to check
