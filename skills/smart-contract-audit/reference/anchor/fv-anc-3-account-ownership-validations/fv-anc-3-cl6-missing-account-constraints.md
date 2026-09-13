# FV-ANC-3-CL6 Missing Account Constraints

## TLDR

Anchor constraints such as `has_one`, `constraint`, and `address` enforce relational correctness between accounts at the framework level. Omitting these constraints forces the instruction body to perform manual checks, and if those checks are also absent, an attacker can pass unrelated accounts.

## Detection Heuristics

**Missing has_one on Relational Fields**
- `Account<'info, Vault>` struct contains an `admin: Pubkey` field but the context does not include `#[account(has_one = admin)]`, allowing any signer to be passed as admin
- Loan, position, or order accounts that reference a user or mint pubkey without a `has_one` constraint linking them to the corresponding account in the context

**Missing address Constraint for Known Fixed Accounts**
- Sysvar, program, or well-known singleton account accepted without `#[account(address = known_id)]`
- Token program, System Program, or Rent sysvar passed as `AccountInfo` without address verification

**Missing constraint for Business Logic Invariants**
- Two accounts that must differ (e.g., source and destination token accounts) lack `constraint = a.key() != b.key()`
- Numerical invariants (e.g., `amount > 0`, `deadline > clock.unix_timestamp`) not enforced at the account constraint level or in the instruction entry

## False Positives

- Constraint enforced equivalently inside the instruction body with a `require!` macro, providing the same security guarantee
- Relationship is structurally impossible to violate due to how the PDA seeds are constructed
