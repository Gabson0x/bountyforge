# FV-ANC-5-CL9 CPI Privilege Escalation via Account Authority

## TLDR

When accounts passed into a CPI carry `is_writable` or `is_signer` flags that originated from the outer transaction context, an attacker can escalate privileges inside the CPI by crafting the outer transaction's account flags. Anchor's `CpiContext` does not automatically strip or re-derive account privilege flags; the program must construct them from protocol logic rather than forwarding them from the incoming accounts.

## Detection Heuristics

**Raw AccountInfo Forwarded to CPI**
- `account.to_account_info()` called directly on an incoming account and the result passed to a CPI without explicitly setting `is_signer: false` or `is_writable: false` where those privileges should not be forwarded
- `CpiContext::new` constructed from accounts list built by iterating `ctx.remaining_accounts` and passing each entry through without flag validation
- Program does not verify that an account's `is_signer` flag in the incoming transaction context corresponds to an expected signer key before relying on it inside a CPI

**Authority Account Not Key-Validated**
- Account is accepted as an authority in the CPI accounts list without comparing its key against a stored expected authority address
- Writable flag forwarded to an account that should only be read during the inner CPI, allowing the CPI target to modify it

**Elevated CPI Privilege Without Explicit Grant**
- Inner CPI receives signer authority over accounts not owned by the calling program, derived from outer transaction signer flags the calling program did not explicitly grant
- `invoke` (not `invoke_signed`) called with accounts carrying signer flags set to true from the outer transaction, propagating caller-level authority into the CPI

## False Positives

- Anchor typed CPI helpers (e.g., `token::transfer`, `system_program::create_account`) construct the account list with explicit flag values and do not forward raw AccountInfo flags from the context
- Program explicitly reconstructs each account's `AccountMeta` with hardcoded `is_signer` and `is_writable` values appropriate to the inner CPI's expected interface
