# FV-ANC-3-CL9 Using ctx.remaining_accounts Without Manual Discriminator Check

## TLDR

Accounts from `ctx.remaining_accounts` bypass Anchor's automatic discriminator verification. Without checking the first 8 bytes against the expected Anchor discriminator, an attacker can pass an account of a different struct type that shares the same owner program, leading to type confusion.

## Detection Heuristics

**Deserialization Without Discriminator Verification**
- `MyAccountType::try_from_slice(&account.data.borrow())` or `MyAccountType::try_deserialize(&mut ...)` called on a `remaining_accounts` entry without first verifying `&data[..8] == MyAccountType::DISCRIMINATOR`
- Account data interpreted as a specific struct type using only owner check, not discriminator check

**Type Cosplay via remaining_accounts**
- Program has multiple account types with the same owner (the program itself); code picks an account from `remaining_accounts` and reads it as type A without discriminating it from type B

**Generic Data Reads Skipping Discriminator**
- Code reads specific byte offsets from `remaining_accounts` entries as if the account structure is known, without validating the discriminator that would confirm the structure

## False Positives

- Account is a token account or system account whose structure is fixed by an external program and does not use Anchor discriminators; the owner check alone is sufficient
- Account type is confirmed by an address constraint that uniquely identifies the account
