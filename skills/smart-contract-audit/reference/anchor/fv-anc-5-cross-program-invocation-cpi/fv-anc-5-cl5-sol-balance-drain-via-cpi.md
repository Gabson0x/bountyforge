# FV-ANC-5-CL5 SOL Balance Drain via CPI

## TLDR

When a program passes an account with a SOL balance to an external program via CPI, the callee can debit lamports from that account if it holds write authority. Without checking the balance before and after the CPI, the caller cannot detect or prevent unexpected lamport drain.

## Detection Heuristics

**Writable Account With SOL Balance Passed to CPI Without Balance Check**
- Vault, user, or program-owned account with a significant lamport balance passed as writable to a CPI without recording `account.lamports()` before the call
- No post-CPI assertion that `account.lamports() >= pre_cpi_balance` or equivalent invariant check

**Signed Accounts Passed Writable to External Programs**
- PDA with lamports passed as a writable signer to a CPI targeting an unaudited program
- User account passed as writable when the CPI only needs it for identification

**No Minimum Balance Enforcement**
- After CPI, no check that the account retains at least its rent-exempt minimum lamport balance
- Program's own treasury or fee accounts passed to CPIs without post-call balance assertions

## False Positives

- CPI intentionally transfers SOL from the account (e.g., a withdrawal instruction) and the amount is tracked and validated before the CPI
- Callee is the System Program or SPL Token Program and the lamport flow is fully deterministic and verified against instruction parameters
