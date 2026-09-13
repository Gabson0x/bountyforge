# FV-ANC-7-CL2 Using init with an ATA

## TLDR

Using `#[account(init, associated_token::...)]` on a token account fails if the ATA already exists, because `init` requires the account to be uninitialized. Any user who pre-creates the ATA before the instruction runs triggers a transaction failure, producing a denial-of-service vector.

## Detection Heuristics

**init Constraint on Associated Token Account**
- `#[account(init, payer = ..., associated_token::mint = ..., associated_token::authority = ...)]` applied to an ATA that may have been created externally before the instruction is called
- Instruction documented as idempotent but uses `init` which is not idempotent for pre-existing accounts

**ATA Creation in Permissionless or User-Facing Instructions**
- `init` on an ATA in a public instruction callable by any user, where any participant can pre-create the ATA to block others
- Protocol initialization flow that creates ATAs for all participants using `init` without considering pre-existing accounts

**Error Handling Does Not Account for AlreadyInUse**
- No fallback logic for `ErrorCode::AccountAlreadyInUse` in the client or program, causing silent failures when ATA exists

## False Positives

- ATA creation is in a one-time admin initialization instruction where the admin controls the timing and pre-creation is not possible by unprivileged users
- Program explicitly checks for and handles the pre-existing ATA case before the `init` instruction is reached
