# FV-ANC-4-CL1 Using create_program_address

## TLDR

`Pubkey::create_program_address` requires a caller-supplied bump seed and does not find the canonical bump. An attacker can supply a non-canonical bump that produces a valid but unintended PDA, bypassing seed-based access controls or creating collisions with legitimate PDAs.

## Detection Heuristics

**create_program_address Without Canonical Bump Verification**
- `Pubkey::create_program_address(&[seed, &[bump]], program_id)` where `bump` comes from instruction data or an account field without verifying it is the canonical bump returned by `find_program_address`
- No comparison of the derived PDA against `Pubkey::find_program_address` output to confirm canonicity

**Bump Stored Without Derivation Check**
- Bump value stored in an account during initialization without verifying it was obtained from `find_program_address`
- Instruction accepts a `bump: u8` parameter and uses it directly in `create_program_address` without on-chain verification

**Missing seeds Constraint in Anchor**
- PDA account declared in a context struct without `#[account(seeds = [...], bump)]`, which would have Anchor enforce canonical bump derivation

## False Positives

- Bump is stored in the PDA account itself during `init` using Anchor's `bump` constraint, and subsequent instructions read it with `#[account(seeds = [...], bump = account.bump)]`, which enforces the canonical value
- `find_program_address` is called in the same instruction and the result is immediately compared, making the use of `create_program_address` equivalent
