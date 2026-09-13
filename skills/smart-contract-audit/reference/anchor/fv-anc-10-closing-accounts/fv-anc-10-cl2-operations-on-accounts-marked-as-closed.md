# FV-ANC-10-CL2 Operations on Accounts Marked as Closed

## TLDR

An account bearing a closed discriminator should be rejected at the start of any instruction that would read or mutate it. Failing to check allows a closed account to be passed into an instruction and processed as if still valid.

## Detection Heuristics

**No Closed-Account Guard at Instruction Entry**
- Instructions that accept an account type that can be closed but do not read the first 8 bytes to compare against the closed discriminator
- `Account<'info, T>` deserialization succeeding even after the closed discriminator is set, because Anchor does not automatically reject closed accounts in all versions

**Stale Data Usage After Closure**
- Code that reads fields from a closed account (e.g., `ctx.accounts.order.amount`) without first verifying the discriminator
- Iteration over a list of accounts from `ctx.remaining_accounts` without per-account closed-discriminator check

**Revival Path Not Guarded**
- Same-transaction revival: an earlier instruction closes the account and a later instruction in the same transaction reads it without discriminator check

## False Positives

- Accounts using Anchor's `#[account(close = destination)]` where the framework enforces the discriminator and subsequent Anchor deserialization automatically rejects closed accounts in newer versions
- Instruction designed specifically to handle the closure lifecycle and intentionally receives closed accounts for cleanup purposes
