# FV-MOV-6-CL4: Dust, Orphaned Dynamic Fields, and Destroy-Zero on Non-Zero

## TLDR

Three related cleanup failures: (1) tiny token amounts ("dust") prevent object closure, enabling attacker to permanently lock victim accounts; (2) parent objects deleted without removing dynamic fields, permanently orphaning stored values; (3) `balance::destroy_zero` called on a potentially non-zero balance, either aborting or silently destroying funds.

## Detection Heuristics

- Search for object close/delete functions and check whether they call `balance::destroy_zero` - trace whether the balance could be non-zero at that point due to dust from fee rounding or partial operations
- Identify every place where dynamic fields are added to objects (`dynamic_field::add`, `dynamic_object_field::add`) and verify a cleanup path exists that removes all of them before the parent is modified or deleted
- Check whether the protocol has a force-close or dust-sweep mechanism for accounts with very small token balances
- Look for griefing vectors: can an attacker send a dust amount to any account to prevent it from being closed? If so, the dust threshold or force-close is missing
- Also check `table::destroy_empty` - calling it on a non-empty table aborts; verify the table is empty before destruction

## False Positives

- Dust threshold defined: balances below the threshold are ignored or swept on close
- Dynamic field cleanup function removes all fields before any object modification
- `balance::destroy_zero` only called after verified-zero balance from prior explicit check
