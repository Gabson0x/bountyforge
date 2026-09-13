# FV-ANC-3-CL8 Using ctx.remaining_accounts Without Manual Ownership Check

## TLDR

`ctx.remaining_accounts` provides raw `AccountInfo` references with no Anchor-enforced constraints. Every account taken from this slice must be manually validated for ownership before its data is read or it is passed to a CPI, otherwise an attacker can substitute an account owned by any program.

## Detection Heuristics

**Direct Data Access From remaining_accounts Without Owner Check**
- `let account = &ctx.remaining_accounts[i]` followed by `account.try_borrow_data()` or deserialization without `require!(account.owner == &expected_program::ID, ...)`
- Loop over `ctx.remaining_accounts` that deserializes each entry without per-entry owner validation

**Accounts From remaining_accounts Forwarded to CPI**
- `AccountInfo` taken from `remaining_accounts` passed directly into a `CpiContext` or `invoke` call without owner verification
- `remaining_accounts` entry used as an authority or signer account in a CPI without checking ownership and key

**Missing Length and Bounds Checks**
- Access to `ctx.remaining_accounts[i]` without verifying the slice has sufficient length, allowing index-out-of-bounds panics

## False Positives

- Account key is fully constrained by a PDA derivation check performed immediately after extracting it from `remaining_accounts`
- Accounts are only used for lamport balance reads, and the program logic is not affected by which program owns the account
