# FV-ANC-3-CL10 Using ctx.remaining_accounts Without Non-Zero Data Check

## TLDR

An uninitialized account on Solana has all-zero data. Accepting such an account from `ctx.remaining_accounts` without checking that it contains non-zero data allows an attacker to pass an empty system account that will be deserialized as a zero-value struct, potentially bypassing balance or state checks.

## Detection Heuristics

**No Liveness Check Before Deserialization**
- `remaining_accounts` entry deserialized or read without verifying that `data.iter().any(|&b| b != 0)` or that the lamport balance is non-zero
- Code assumes a non-zero discriminator check serves as a liveness check, but all-zero data passes byte-equality checks against a zero discriminator

**Zero-Balance Account Accepted as Valid State**
- Account with zero lamports taken from `remaining_accounts` and used as if it represents initialized state
- Missing check for `account.lamports() > 0` before trusting the account as representing a real on-chain entity

**System-Owned Zero Account**
- Account owned by the System Program with zero data accepted and treated as a valid program account of a specific type

## False Positives

- Account is expected to start at zero as part of its initialized state (e.g., a counter initialized to zero); zero data is valid and expected
- Program immediately initializes the account after accepting it and does not read any fields from it prior to initialization
