# FV-ANC-2-CL2 No is_signer Check

## TLDR

When using raw `AccountInfo` or native Solana program patterns, the `is_signer` field on the account info must be explicitly checked. Omitting this check means an instruction accepts any account as an authority without verifying it signed the transaction.

## Detection Heuristics

**Key Comparison Without Signer Verification**
- Code that checks `authority.key != expected_key` or `authority.key() == expected_key` but never checks `authority.is_signer`
- Authorization based solely on account key equality, allowing a known-public-key account to be passed without a signature

**Missing is_signer Guard in Instruction Body**
- Instruction using raw `AccountInfo` for an authority account without `if !account.is_signer { return Err(...) }`
- `require!(account.is_signer, ...)` absent from all code paths that perform privileged operations

**AccountInfo in Context Struct Without Signer Wrapper**
- Multiple `AccountInfo` accounts in a context struct where at least one is treated as an authorizing party in the instruction body, but none have `is_signer` verified

## False Positives

- Account is a PDA controlled by the program; PDAs cannot be signers and authorization is instead proven through seed derivation
- Account is a read-only system account or sysvar where signing is not meaningful
