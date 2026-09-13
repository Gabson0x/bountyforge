# FV-TON-7-CL4 Token Encoding and Accounting

## TLDR

Mixing `store_coins`/`load_coins` (variable-length) with `store_uint`/`load_uint` (fixed-width) on the same field corrupts the cell layout. Using raw contract balance instead of internally tracked deposits allows balance manipulation through direct TON transfers.

## Detection Heuristics

**store_coins / load_coins mismatch**
- Field written with `store_coins(amount)` but read with `load_uint(64, ...)` - `store_coins` uses a 4-bit length prefix that `load_uint` does not skip, causing all subsequent fields to be read from incorrect bit offsets
- Reverse: written with `store_uint(amount, 120)` but read with `load_coins()` - `load_coins` reads the length prefix from what is actually data bits

**Zero-amount coins encoding**
- `store_coins(0)` encodes as 4 bits (length prefix = 0) - code that assumes zero amounts take zero space miscounts cell layout
- Conditional serialization where zero amounts are omitted but the reader always expects them, or vice versa

**Raw balance for accounting**
- Vault or pool contract uses `my_balance` to calculate share prices or withdrawal amounts - attacker sends TON directly to inflate `my_balance` and manipulate the calculation
- No internal `total_deposits` tracker; all accounting done against raw balance

**Token decimal mismatch**
- Cross-token operations (e.g., swap, collateral) that do not normalize for different decimal precisions - comparing 1 unit of a 6-decimal token to 1 unit of a 9-decimal token as equal
- No per-token decimal metadata stored or applied during calculations

## False Positives

- `store_uint` / `load_uint` used consistently on both sides for a field that is known to fit within the specified bit width and is not a `coins` type field in the TL-B schema
- Balance-based check used only as an upper-bound safety net while a tracked variable is the authoritative accounting value
