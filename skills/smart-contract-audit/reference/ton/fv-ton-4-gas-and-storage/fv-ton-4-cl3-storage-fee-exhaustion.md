# FV-TON-4-CL3 Storage Fee Exhaustion

## TLDR

TON contracts pay continuous storage fees. Without minimum-balance reserves, operations that reduce the balance to near-zero cause the contract to be frozen - permanently inaccessible until someone sends TON to unfreeze it.

## Detection Heuristics

**No raw_reserve before sends**
- `send_raw_message` calls throughout the contract without a preceding `raw_reserve(MIN_TON_FOR_STORAGE, RESERVE_REGULAR)` that protects the minimum viable balance
- Withdraw or refund operations that compute `amount = my_balance - fees` without subtracting a storage reserve

**Mode 128 sends without reserve**
- Sending with mode 128 (all remaining balance) without first reserving storage fees via `raw_reserve` - balance hits zero, storage phase fails on next block, contract freezes

**Unbounded dictionary growth**
- `udict_set` / `dict_set` accumulating entries on every user interaction without a `MAX_ENTRIES` check - growing state increases storage fees proportionally, eventually making the contract economically unviable
- No cleanup or expiry mechanism for old dictionary entries

**Long-lived contracts without storage budget**
- Contract expected to be live for months or years but no storage fee analysis was performed - initial TON balance insufficient to sustain storage fees over the protocol's lifetime

## False Positives

- Contract is short-lived by design (single-use escrow, one-time action) and the deployer accounts for the total storage cost at deployment
- Storage reserve implemented in a shared helper function called at the start of every handler - verify it is called on all execution paths
