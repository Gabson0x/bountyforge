# FV-ANC-4-CL5 PDA Used as Signer Without Ownership Verification

## TLDR

Using `invoke_signed` with PDA seeds to authorize a CPI without first verifying the PDA account is owned by the calling program allows a forged PDA from a different program to authorize operations it should not perform. If two programs can derive the same address from the same seeds, the legitimate program's invoke_signed call can be exploited using an account initialized by the attacker's program.

## Detection Heuristics

**No Owner Check Before invoke_signed**
- `invoke_signed` call where the PDA authority account's owner field is not compared against the current program ID (`*ctx.program_id`)
- PDA passed as an authority in a token transfer or system instruction without `constraint = pda_account.owner == *ctx.program_id`
- Program derives a PDA, passes it as a signer, but does not verify the account at that address was initialized by the same program

**Cross-Program Seed Collision**
- Program derives a PDA using seeds that are not globally unique (e.g., `[b"authority"]` without the program ID embedded); a different program using the same seeds produces the same address
- No program-specific discriminator or program ID embedded in seeds to prevent another program from pre-initializing the PDA before the legitimate program

**Anchor Account Without Owner Constraint**
- `UncheckedAccount` used for a PDA signer without a manual `require_eq!(account.owner, *ctx.program_id)` check
- `AccountInfo` for a PDA authority accepted directly in the accounts struct without an `#[account(owner = crate::ID)]` constraint

## False Positives

- Anchor's `Account<'_, T>` struct enforces owner check automatically; any PDA loaded via typed accounts is guaranteed to be owned by the calling program
- PDA seeds include the current program ID as a seed component, making cross-program seed collision impossible
