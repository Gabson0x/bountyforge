# FV-ANC-6-CL1 Unclear Error Messages

## TLDR

Using generic Solana `ProgramError` variants instead of custom Anchor error codes makes it impossible for clients, indexers, and auditors to determine why a transaction failed. Opaque errors also impede incident response and make it harder to distinguish security-critical rejections from benign validation failures.

## Detection Heuristics

**Generic ProgramError Variants Used for Business Logic Failures**
- `return Err(ProgramError::InvalidArgument.into())` or `return Err(ProgramError::InvalidAccountData.into())` used where a specific custom error would convey the actual condition
- `ProgramError::Custom(n)` with a numeric code and no corresponding enum variant or documentation

**Absence of #[error_code] Enum**
- Program has no `#[error_code]` enum defined, meaning all errors propagate as generic program errors
- `#[error_code]` enum exists but contains a single generic variant used for all failure cases

**Missing #[msg] Annotations**
- `#[error_code]` enum variants lack `#[msg("...")]` annotations, producing error codes without human-readable descriptions
- Error messages are present but do not describe the specific invariant that was violated

## False Positives

- `ProgramError` variants are used for infrastructure-level errors (e.g., serialization failures, account not found) where a generic error is appropriate
- Program is an internal helper with no external clients and error granularity is not operationally required
