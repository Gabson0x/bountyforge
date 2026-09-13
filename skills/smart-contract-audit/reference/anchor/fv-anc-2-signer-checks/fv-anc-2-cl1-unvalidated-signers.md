# FV-ANC-2-CL1 Unvalidated Signers

## TLDR

Declaring an account as `AccountInfo<'info>` rather than `Signer<'info>` in an Anchor context struct means the framework does not enforce that the account signed the transaction. Any public key can be passed as the authority without authorization.

## Detection Heuristics

**AccountInfo Used Where a Signer Is Required**
- Account declared as `pub authority: AccountInfo<'info>` in a context struct for an instruction that performs privileged operations
- Account used to authorize transfers, mutations, or admin actions but typed as `AccountInfo` instead of `Signer`

**No Supplemental is_signer Check**
- `AccountInfo` account used in a privileged path without a subsequent `require!(ctx.accounts.authority.is_signer, ...)` check in the instruction body
- `has_one` constraint on a vault pointing to an `AccountInfo` authority without signer enforcement

**Signer Constraint Missing on PDA-Signed Paths**
- Instruction accepts a user-provided authority for a PDA operation but does not enforce signing from that authority before deriving or using the PDA

## False Positives

- `AccountInfo` is used for read-only informational accounts (e.g., sysvars, program IDs) where signing is not required
- Account is a PDA that cannot sign transactions; signer seeds are instead validated via `invoke_signed` or Anchor seeds constraint
