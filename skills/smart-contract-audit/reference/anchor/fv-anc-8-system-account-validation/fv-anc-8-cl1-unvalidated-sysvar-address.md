# FV-ANC-8-CL1 Unvalidated Sysvar Address

## TLDR

Solana sysvars (Clock, Rent, SlotHashes, etc.) have fixed public addresses. If a sysvar is accepted as an `AccountInfo` without verifying its address, an attacker can substitute a different account, causing the program to read attacker-controlled data as if it were the sysvar.

## Detection Heuristics

**Sysvar Accepted as AccountInfo Without Address Constraint**
- `pub rent: AccountInfo<'info>` or `pub clock: AccountInfo<'info>` in a context struct without `#[account(address = sysvar::rent::ID)]` or equivalent
- Sysvar account deserialized using `Rent::from_account_info(&ctx.accounts.rent)` without a prior address check

**Missing address Constraint on Sysvar Accounts**
- Sysvar fields in Anchor context structs declared as `AccountInfo` instead of the typed `Sysvar<'info, Rent>` or `Sysvar<'info, Clock>` wrappers
- No `require!(ctx.accounts.rent.key() == sysvar::rent::ID, ...)` in the instruction body when `AccountInfo` is used

**Sysvar Data Read Without Identity Verification**
- `Rent::try_from_slice(&account.data.borrow())` called on an account not verified to be the Rent sysvar
- Clock fields (e.g., `unix_timestamp`, `slot`) read from an account without confirming it is the Clock sysvar

## False Positives

- Anchor typed sysvar wrappers `Sysvar<'info, Clock>` or `Sysvar<'info, Rent>` used, which enforce address validation automatically
- Sysvar accessed via `Clock::get()` or `Rent::get()` syscalls, which retrieve the canonical sysvar data without account passing
