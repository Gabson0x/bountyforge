# FV-SOL-5-C10 Data Structure State Integrity

## TLDR

Three related patterns where data structure operations leave inconsistent state:

- **Array delete gap**: `delete array[index]` zeroes the element but does not shift or shrink - iteration over the array sees phantom zero-value entries.
- **Duplicate items in user-supplied array**: no deduplication check allows a user to pass the same ID multiple times in one call, repeatedly applying an action intended to occur once.
- **Nested mapping not cleared on struct delete**: `delete myMapping[key]` zeroes primitive fields but cannot clear nested `mapping` or dynamic array fields - reused keys expose stale values.

## Detection Heuristics

**Array Delete Gap**
- `delete array[index]` followed by iteration over `array` (not using swap-and-pop)
- Distribution loop: `for (i; i < arr.length; i++) transfer(arr[i], ...)` after element deletion
- `arr.length` unchanged after delete - loop visits zero-address entries

**Duplicate Array Items**
- Function accepts `uint256[]` or `address[]` parameter (tokenIds, positions, claimIds)
- No `require(!seen[id])` guard or sorted-unique check
- State zeroed inside loop body - second iteration sends 0 (if not reverted) or double-charges

**Nested Mapping Not Cleared**
- `delete myMapping[key]` on a struct type containing `mapping` fields
- Key reused after deletion - stale nested values accessible
- Approvals, allowances, or configuration sub-maps not explicitly cleared before reuse

## False Positives

- Swap-and-pop used for all array element removal
- Sorted-unique input enforced: `require(ids[i] > ids[i-1])`
- Deduplication via `mapping(id => bool) seen` reset per call
- State change (zero-out) happens before any transfer in loop - second duplicate reverts naturally
- Nested mapping cleared manually before struct delete or key reuse explicitly prevented
