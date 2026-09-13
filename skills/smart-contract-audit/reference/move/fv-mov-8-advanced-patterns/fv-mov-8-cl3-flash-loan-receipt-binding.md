# FV-MOV-8-CL3: Flash Loan Receipt Pool Binding and Nested Start

## TLDR

Two confirmed critical flash loan findings from real audits: (1) receipt struct has no `pool_id` field - repay function accepts receipts from Pool A to settle loans from Pool B (Cetus, Dexlyn); (2) flash loan `start` callable multiple times in the same PTB - second call resets the balance snapshot so `finish` validates against the wrong baseline, allowing underpayment.

## Detection Heuristics

- Check the flash loan receipt struct definition for a `pool_id: ID` field
- In the `repay` or `return_flash_loan` function, verify `assert!(receipt.pool_id == object::id(pool))`
- For the nested start vulnerability: check the `start` or `borrow` function - does it check for an existing active loan (e.g., `assert!(!pool.loan_active)`) before creating the receipt?
- If the receipt snapshot stores the pre-loan balance, verify a "loan active" mutex prevents the snapshot from being overwritten by a second `start` call
- Trace whether `finish` or `repay` reads the actual current balance and compares it to the receipt's recorded amount - or trusts the receipt's amount directly without re-reading state

## False Positives

- `pool_id: ID` field present in receipt struct and validated in repay function
- `start` function checks for existing active loan and aborts if one exists
- `finish` reads actual balance from the pool object, not from receipt fields
