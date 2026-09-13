# FV-ANC-3-CL4 Usage of UncheckedAccount Without Manual Signer Check

## TLDR

When `UncheckedAccount<'info>` is used for an account that is expected to authorize an action, the `is_signer` field must be explicitly checked in the instruction body. Anchor does not perform this check automatically for unchecked account types.

## Detection Heuristics

**UncheckedAccount Used as Authority Without Signer Verification**
- `pub authority: UncheckedAccount<'info>` in a context struct where the instruction performs privileged operations gated on this account
- No `require!(ctx.accounts.authority.is_signer, ...)` in the instruction body when `UncheckedAccount` is the authorizing party

**Key Equality Check Without Signer Check**
- Code verifies `authority.key() == expected_key` but omits `authority.is_signer`, allowing signature replay or impersonation
- `has_one` constraint on a related account pointing to an `UncheckedAccount` without enforcing that it signed

**`/// CHECK:` Justification Omits Signer Rationale**
- `/// CHECK:` comment explains ownership but does not address how signer status is enforced

## False Positives

- `UncheckedAccount` used for a PDA that authorizes via seeds rather than a signature
- Account is used purely for reading data and no privileged action is gated on it being a signer
