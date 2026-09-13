# FV-MOV-4-CL2: Hot Potato Flash Loan Pattern Errors

## TLDR

The hot potato pattern enforces flash loan repayment by making the receipt struct have no abilities - the compiler requires it to be consumed in the same PTB. Two failure modes: (1) receipt struct has `drop` or `store` ability, breaking enforcement; (2) receipt does not bind to the originating pool ID, allowing cross-pool repayment.

## Detection Heuristics

- Find flash loan receipt / borrow receipt structs and verify their ability list is empty (no `copy`, `drop`, `store`, `key`)
- Verify the receipt struct contains a `pool_id: ID` field storing the originating pool's object ID
- In the `repay` function, verify `assert!(receipt.pool_id == object::id(pool), EPoolMismatch)` is present
- Search for flash loan `start` or `borrow` functions - check whether calling `start` a second time in the same PTB overwrites an existing receipt snapshot without aborting (nested start vulnerability)
- Verify the repay function checks `returned_amount >= receipt.amount + fee`, not just that the receipt is consumed

## False Positives

- Receipt struct intentionally has `key` ability only (creates an object) with no `drop` or `store`; compiler still enforces consumption via object model
- Protocol uses an alternative enforcement mechanism: shared object state flag checked at transaction end
- Pool ID binding present and validated correctly in repay function
