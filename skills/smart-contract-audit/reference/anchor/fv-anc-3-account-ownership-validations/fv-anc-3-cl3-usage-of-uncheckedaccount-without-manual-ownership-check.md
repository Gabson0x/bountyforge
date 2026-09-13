# FV-ANC-3-CL3 Usage of UncheckedAccount Without Manual Ownership Check

## TLDR

`UncheckedAccount<'info>` explicitly bypasses Anchor's automatic ownership and discriminator verification. Any instruction using this type must manually perform the ownership checks that `Account<'info, T>` would otherwise enforce, or an attacker can supply an account owned by any program.

## Detection Heuristics

**UncheckedAccount Without owner Constraint or Manual Check**
- `pub some_account: UncheckedAccount<'info>` in a context struct without `#[account(owner = expected_program_id)]` constraint
- `UncheckedAccount` used in an instruction body that reads or writes structured data without a preceding `require!(account.owner == &expected_program::ID, ...)`

**`/// CHECK:` Comment Absent or Inadequate**
- Anchor requires a `/// CHECK:` doc comment above every `UncheckedAccount` field; absence suggests the safety rationale was not considered
- `/// CHECK:` comment present but only states "safe" without explaining why owner verification is unnecessary

**UncheckedAccount Passed to CPI Without Validation**
- `UncheckedAccount` forwarded to a CPI without verifying its owner, allowing an attacker-controlled account to be interpreted as a legitimate target by the callee

## False Positives

- `UncheckedAccount` used for accounts whose key is fully constrained by `#[account(address = known_constant)]`, making ownership implied
- Account is a program account (executable) where owner is always the BPF loader and ownership of the program itself is not relevant
