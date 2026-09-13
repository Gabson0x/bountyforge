# FV-TON-4-CL4 Gas Draining and Unbounded Loops

## TLDR

Spam of invalid external messages drains contract balance via repeated `accept_message()` calls, and unbounded iteration over dictionaries or user-controlled data structures exhausts the transaction gas limit, leaving state inconsistent.

## Detection Heuristics

**External message gas draining**
- `accept_message()` called before signature validation or seqno check - every incoming external message (valid or not) charges gas from the contract balance
- No minimum-balance enforcement before `accept_message()`, allowing the contract to be drained to zero through spam

**Unbounded loop over dictionary**
- `while` or `do ... until` loop iterating over a dictionary without a `MAX_ITERATIONS` limit
- `dict_get_next` / `udict_get_next` in a loop that grows with user input - attacker adds entries to force expensive iteration
- Batch operations (distribute rewards to all holders, update all positions) that process the entire dictionary in one transaction

**Missing dust amount rejection**
- No `throw_unless(error::amount_too_small, amount >= MIN_VIABLE_AMOUNT)` - processing economically insignificant amounts costs more in gas than the operation is worth, enabling griefing via flood of dust transactions

**Recursive cell structures**
- TVM stack overflow from recursive cell unpacking or deeply nested message parsing - cells-within-cells exceeding max depth of 256 or stack depth limit

## False Positives

- Loop is bounded by a hard-coded constant or a protocol invariant that limits the maximum number of dictionary entries
- External message handler has a cheap seqno check as the very first operation before `accept_message()` - gas exposure per invalid message is minimal and bounded
