# FV-MOV-1-CL2: Drop Ability Enables Debt Destruction

## TLDR

An obligation object (flash loan receipt, debt record, collateral lock, vesting lock) granted the `drop` ability can be silently discarded. A borrower drops the receipt without repaying; a collateral lock is dropped to unlock assets early.

## Detection Heuristics

- Search all structs used as flash loan receipts, debt records, escrow locks, or collateral proofs for `drop` in their ability list
- In any function that creates a receipt-like struct, trace whether the compiler is forced to consume it - if `drop` is present, the compiler never enforces consumption
- A hot potato struct (no abilities) is the correct pattern: the compiler requires every value to be moved or explicitly consumed; `drop` bypasses this guarantee
- Look for `let receipt = borrow(...)` patterns where the caller's code path can exit without calling `repay(receipt)`

## False Positives

- Struct has no obligation semantics - it is purely informational and dropping it is safe
- `drop` is intentional and documented; all code paths correctly handle both the consumption and drop cases
- Protocol uses an alternative enforcement mechanism (e.g., shared object state flag checked at end of transaction)
