# FV-ANC-7-CL3 Token-2022 Incompatibility

## TLDR

The legacy SPL Token program and Token-2022 have different program IDs and different instruction formats for operations like `transfer`. Code that hardcodes `anchor_spl::token` will fail or behave incorrectly when used with Token-2022 mints, which introduce transfer fees, interest, confidential transfers, and other extensions.

## Detection Heuristics

**anchor_spl::token Instead of anchor_spl::token_interface**
- `use anchor_spl::token::{Transfer, transfer}` used in an instruction that is intended to support both Token and Token-2022 mints
- `token::transfer(cpi_ctx, amount)` called instead of `token_interface::transfer_checked(cpi_ctx, amount, decimals)`

**Hardcoded Token Program ID in Constraints**
- `#[account(address = spl_token::ID)]` on a token program account when the protocol intends to support Token-2022
- `token_program: Program<'info, Token>` in the context struct instead of `token_program: Interface<'info, TokenInterface>`

**Missing Mint Account in transfer_checked Calls**
- `transfer` used instead of `transfer_checked`, omitting the mint account parameter required by Token-2022 for fee calculation
- Protocol does not pass the mint account to token operation CPIs, making it incompatible with fee-on-transfer extensions

**No Extension Checks for Transfer Fee or Other Hooks**
- Program does not inspect mint extension data to account for transfer fees before computing expected received amounts
- Transfer hook extensions not handled, causing unexpected behavior on Token-2022 mints with hooks

## False Positives

- Protocol explicitly restricts itself to legacy SPL Token mints and enforces this via mint account ownership checks against `spl_token::ID`
- Token-2022 extensions are irrelevant for the specific mint the protocol uses, and this is enforced by a constraint on the mint account
