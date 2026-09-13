# FV-ANC-11-CL2 Lamport Balance Invariant Violation in CPI

## TLDR

Solana programs that perform CPIs can inadvertently violate the lamport conservation invariant: the total lamports across all accounts touched by a transaction must be the same before and after. If a program transfers lamports via a CPI and also modifies account data in ways that change the rent-exempt minimum, the transaction may fail or leave an account in a state where it is no longer rent-exempt and subject to garbage collection.

## Detection Heuristics

**Lamports Transferred Without Rent Check**
- CPI that transfers lamports out of an account does not verify the sender's remaining balance meets the rent-exempt minimum for its current data size
- Lamport transfer amount is the full account balance without checking `Rent::minimum_balance(data.len())`
- After a CPI closes a sub-account and sweeps lamports, the receiving account's balance not verified to remain rent-exempt

**CPI Balance Accounting Mismatch**
- Program tracks lamport balances in account state fields but the tracked value diverges from the actual `account.lamports()` after a CPI; subsequent logic uses the stale tracked value
- Balance change from one CPI is not accounted for before a second CPI in the same instruction, leading to cumulative invariant violation
- Program attempts to transfer more lamports than the source account holds; no `require!(source.lamports() >= amount)` check before the CPI

**Rent Exemption After Realloc**
- Account data is reallocated to a larger size via `AccountInfo::realloc` but no additional lamports are transferred to cover the increased rent-exempt minimum
- Realloc and lamport top-up are performed in separate instructions, creating a window where the account is non-rent-exempt

## False Positives

- All lamport transfers validated against account balance and rent-exempt minimum before execution
- Anchor `#[account(mut, close = recipient)]` constraint handles lamport sweep and zero-fill atomically with correct rent accounting
