# FV-ANC-10-CL1 Closing Accounts Without Zeroing Data and Setting a Closed Discriminator

## TLDR

Manually closing an account by zeroing its lamports without also zeroing its data and writing a closed discriminator leaves the account readable as if still active. An attacker can revive the account within the same transaction or exploit the stale data in subsequent instructions.

## Detection Heuristics

**Lamport Drain Without Data Zeroing**
- Code that sets `**ctx.accounts.account.lamports.borrow_mut() = 0` without subsequently zeroing all bytes in the account data
- Manual closure not using Anchor's `close` constraint, combined with absence of a `try_borrow_mut_data()` zeroing loop

**No Closed Discriminator Written**
- After lamport drain, the first 8 bytes of account data are not overwritten with a sentinel value (e.g., `CLOSED_ACCOUNT_DISCRIMINATOR` from the Anchor source)
- Anchor's own `AccountsClose` trait not used and no equivalent discriminator write present

**Revival Attack Surface**
- Account closed and re-funded within a single transaction using separate instructions, allowing data to persist and be read again
- No check at the start of any instruction that consumes this account type to reject accounts bearing the closed discriminator

## False Positives

- Anchor `#[account(close = destination)]` constraint used correctly, as Anchor handles zeroing and discriminator writing internally
- Accounts closed via `close_account` CPI to the System Program where the runtime reclaims data automatically on account deletion
