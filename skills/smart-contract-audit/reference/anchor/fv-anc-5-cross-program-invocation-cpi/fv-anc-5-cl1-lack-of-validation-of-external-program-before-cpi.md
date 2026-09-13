# FV-ANC-5-CL1 Lack of Validation of External Program Before CPI

## TLDR

When the program ID for a CPI target is passed as an account in the transaction rather than hardcoded, an attacker can substitute a malicious program. Without validating the program ID before calling, the CPI executes arbitrary attacker-controlled code with the caller's account context.

## Detection Heuristics

**Program Account Used Without Key Comparison**
- `ctx.accounts.external_program.to_account_info()` passed to `CpiContext::new` or `invoke` without first comparing `ctx.accounts.external_program.key()` against a known program ID constant
- `AccountInfo` for a program accepted in the context struct as `external_program: AccountInfo<'info>` without an `#[account(address = expected_program_id)]` constraint

**Dynamic Program Selection Without Allowlist**
- Program ID derived from user input or an account field without an allowlist check
- CPI target varies by instruction parameter and no exhaustive match or set-membership check is performed

**Missing Program Executable Check**
- Program account not verified to be executable (`account.executable == true`) before use as a CPI target

## False Positives

- Program ID is fully constrained by `#[account(address = spl_token::ID)]` or equivalent Anchor address constraint
- CPI uses Anchor's typed CPI helpers (e.g., `token::transfer`, `system_program::transfer`) which hardcode the target program ID internally
