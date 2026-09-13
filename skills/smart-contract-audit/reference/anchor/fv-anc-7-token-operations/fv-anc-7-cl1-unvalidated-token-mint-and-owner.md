# FV-ANC-7-CL1 Unvalidated Token Mint and Owner

## TLDR

Token accounts on Solana carry a `mint` and an `owner` field. Without validating both, an attacker can substitute a token account for a different mint (causing the program to treat the wrong token as the expected asset) or a different owner (allowing unauthorized access to balances).

## Detection Heuristics

**Token Account Accepted Without mint Constraint**
- `Account<'info, TokenAccount>` in a context struct without `#[account(token::mint = expected_mint)]` or equivalent `constraint = token_account.mint == expected_mint.key()`
- Token account deserialized and used without checking `.mint` against the program's known mint address

**Token Account Accepted Without authority/owner Constraint**
- Token account accepted without `#[account(token::authority = expected_authority)]` or a manual check that `token_account.owner == expected_owner.key()`
- Instruction performs a debit or credit on a token account without verifying it belongs to the expected user

**Both mint and owner Unchecked**
- `InterfaceAccount<'info, TokenAccount>` or `Account<'info, TokenAccount>` used raw without either mint or owner validation, relying solely on the account being owned by the Token Program

## False Positives

- Token account is an ATA derived on-chain from the user and mint via `#[account(associated_token::mint = mint, associated_token::authority = user)]`, which implicitly enforces both mint and owner
- Mint is validated via a separate `has_one = mint` constraint on a vault account that also stores the mint pubkey
