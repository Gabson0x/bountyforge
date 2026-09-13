# FV-MOV-4-CL1: Shared Object Race Conditions and Lost Updates

## TLDR

Concurrent transactions targeting the same shared object can interleave reads and writes without a version or sequence check. The second writer overwrites the first writer's result, causing lost updates - for example, two deposits each read `total = 100`, add their amounts independently, and both write back, erasing the first deposit.

## Detection Heuristics

- Identify all shared objects and their mutating functions
- Check whether every mutating function reads, modifies, and writes back a `version: u64` field atomically - a transaction with a stale version should abort
- Look for patterns where two independent values (e.g., `total_deposited` and `user_balance`) are both updated in the same function but neither is version-checked
- In DEX or lending protocols, the primary pool or reserve object is the critical shared state - verify it has version protection
- Also check for `sequence_number` or `nonce` fields used for ordering protection

## False Positives

- Sui's object versioning at the consensus layer prevents two transactions from writing the same object version - the second will fail automatically; assess whether this is sufficient for the specific operation
- Operations are commutative and ordering is irrelevant (e.g., incrementing a pure counter)
- Single-writer pattern enforced - only one authorized function can mutate the object
