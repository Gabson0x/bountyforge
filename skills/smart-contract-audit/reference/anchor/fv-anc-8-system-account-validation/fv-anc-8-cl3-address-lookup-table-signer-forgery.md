# FV-ANC-8-CL3 Address Lookup Table Signer Forgery

## TLDR

Address Lookup Tables (ALTs) expand transaction account lists from compressed indices. A malicious transaction can use an ALT to inject accounts that appear at indices the program expects to belong to specific signers or programs. Programs that identify accounts by position rather than by explicit key comparison are vulnerable to position-based spoofing via ALT-injected accounts.

## Detection Heuristics

**Positional Account Access Without Key Comparison**
- Program accesses `ctx.remaining_accounts[n]` or instruction accounts by a positional index and trusts the account at that position without comparing its `key()` against an expected constant or stored address
- Signer status of an ALT-resolved account trusted without re-verifying the account key matches the expected signer

**ALT Injection Path**
- Transaction account list extended via an ALT that the attacker controls; attacker can populate the ALT with accounts that mimic expected positions
- Program does not check whether an account at a given position originated from a static account reference or from an ALT resolution
- Expected program ID account (e.g., Token program, System program) verified only by position without comparing the key at runtime

**No Address Constraint on Critical Accounts**
- Critical authority or program accounts accepted without Anchor's `#[account(address = expected_key)]` constraint
- Accounts in `ctx.remaining_accounts` parsed and acted upon without building a validated allowlist before the first operation

## False Positives

- Every account is validated by comparing its key against a hardcoded constant or a stored expected address, making position irrelevant
- Anchor `#[account(address = known_constant)]` constraint applied to all critical accounts, ensuring key equality before any account data is accessed
