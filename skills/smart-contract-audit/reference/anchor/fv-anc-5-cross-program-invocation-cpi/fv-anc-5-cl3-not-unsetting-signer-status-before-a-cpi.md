# FV-ANC-5-CL3 Not Unsetting Signer Status Before a CPI

## TLDR

When a user-signed account is passed into a CPI, the callee receives it with `is_signer = true`. A malicious or compromised callee can exploit this elevated status to perform privileged operations on the user's account that the caller did not intend to authorize.

## Detection Heuristics

**User AccountInfo Passed to CPI Without Clearing is_signer**
- `ctx.accounts.user.to_account_info()` included in the accounts list for a CPI without setting `account_info.is_signer = false` before the call
- `invoke_signed` or `CpiContext` constructed with an accounts list that includes user-signed accounts whose signer status has not been cleared

**Signer Accounts Forwarded to Untrusted Programs**
- CPI target is not a well-known audited program; passing signers to an unknown program extends unintended trust
- Multiple accounts with `is_signer = true` forwarded to a CPI when only the PDA needs to sign

**Signer Status Cleared Only for Some Accounts**
- Code clears `is_signer` for the PDA but not for user accounts, or vice versa, leaving unintended signers in the CPI account list

## False Positives

- CPI is to a well-known program (SPL Token, System Program) and the user's signer status is required for the operation (e.g., user-initiated transfer)
- Signer status is intentionally forwarded and the callee program is trusted and audited to not misuse it
