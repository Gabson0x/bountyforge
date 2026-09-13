# FV-MOV-6-CL3: Fee Accounting Errors

## TLDR

Fee bypass occurs when an alternate code path (emergency withdraw, admin withdraw, batch operation) skips the fee calculation. Non-atomic fee deduction allows a PTB to skip the fee step. Missing fee withdrawal function locks protocol revenue permanently.

## Detection Heuristics

- Map all exit paths from a vault or pool: normal withdrawal, emergency withdrawal, admin withdrawal, batch withdrawal - verify every path calls the same fee calculation function
- Check whether fee deduction is in a separate function from the main operation; in a PTB, the caller controls execution order and could omit the fee step
- Search for fee collection logic that increments a `fee_balance` or `accumulated_fees` counter - verify a corresponding `withdraw_fees` or `claim_fees` function exists and is accessible to the admin
- Verify fee amount calculation uses consistent pre-fee vs post-fee amounts throughout - mixing gross and net amounts creates discrepancies
- `fee_balance == 0` with no withdrawal function in a protocol that claims to collect fees is a strong signal of a missing function

## False Positives

- Single fee calculation helper called from every exit path
- Fee and principal deducted atomically within the same function with no separable steps
- Fee withdrawal function exists and is admin-gated
