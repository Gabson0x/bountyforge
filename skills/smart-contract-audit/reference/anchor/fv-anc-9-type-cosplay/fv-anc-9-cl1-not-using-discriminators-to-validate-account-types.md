# FV-ANC-9-CL1 Not Using Discriminators to Validate Account Types

## TLDR

Anchor automatically prepends an 8-byte discriminator to every `#[account]` struct. When deserializing accounts manually or accepting them via `UncheckedAccount`, failing to check the discriminator allows an attacker to pass an account of a different type that happens to have the same owner program, causing type confusion.

## Detection Heuristics

**Manual Deserialization Without Discriminator Check**
- `MyStruct::try_from_slice(&ctx.accounts.account.data.borrow())` or `AnchorDeserialize::deserialize(&mut data)` called without first verifying `&data[..8] == MyStruct::DISCRIMINATOR`
- `borsh::from_slice` on account data that skips the first 8 bytes without comparing against the expected discriminator

**UncheckedAccount Deserialized Without Discriminator**
- `UncheckedAccount<'info>` data read and interpreted as a known struct without discriminator verification
- Account from `ctx.remaining_accounts` deserialized as `MyAccountType` without checking the discriminator bytes

**Type Cosplay Attack Surface**
- Program has multiple account types with identical field layouts or compatible sizes owned by the same program; without discriminator checks, one can be substituted for another
- Admin, user, and vault account structs with overlapping field offsets and same owner program

## False Positives

- Anchor's `Account<'info, T>` deserialization used, which automatically checks the discriminator during `try_deserialize`
- Account is a token account or system account with a fixed layout defined by an external program that does not use Anchor discriminators; owner check is sufficient
