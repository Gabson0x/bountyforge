# FV-ANC-3-CL13 init_if_needed Without Reinitialization Guard

## TLDR

Anchor's `init_if_needed` skips account creation if the account already exists, but it does not prevent an attacker from pre-creating the PDA with malicious initial state. Without a reinitialization guard in the instruction body, a subsequent call that skips init will silently operate on attacker-controlled data.

## Detection Heuristics

**init_if_needed Without State Validation on Existing Account**
- `#[account(init_if_needed, ...)]` used without any check in the instruction body that verifies the account's existing fields when the account was already initialized
- No `is_initialized` flag or equivalent sentinel checked before writing fields, allowing re-entry to overwrite state

**Pre-Created PDA Attack Surface**
- PDA seeds include only user-controlled inputs (e.g., user pubkey, a name string) allowing an attacker to derive the PDA and create it with arbitrary data before the legitimate user

**Authority Field Not Verified on Existing Account**
- Instruction uses `init_if_needed` for an account that stores an `authority: Pubkey` but does not verify that the stored authority matches `ctx.accounts.user.key()` when the account already exists

**Missing Idempotency Check**
- Instruction is intended to be idempotent but lacks protection against an attacker calling it a second time to reset critical state

## False Positives

- Account is a token account (ATA) where `init_if_needed` is safe because the token program enforces ownership on initialization
- Instruction only writes to the account on first initialization and subsequent calls are no-ops due to explicit guards in the instruction body
