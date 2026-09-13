# FV-TON-7-CL2 Supply Invariants and Burn

## TLDR

`total_supply` must be decremented on every burn. If `burn_notification` is never sent by the wallet, or the minter's handler does not update `total_supply`, the supply is permanently inflated - breaking all calculations that divide by supply.

## Detection Heuristics

**Burn notification not sent**
- Jetton wallet burn handler executes the balance deduction and sends TON to the user but does not send `op::burn_notification` to the minter
- Custom burn path (e.g., admin burn) bypasses the standard TEP-74 flow and omits the notification

**Minter not handling burn_notification**
- Minter contract has no handler for `op::burn_notification` - or the handler exists but does not decrement `total_supply`
- `total_supply -= burn_amount` missing or applied to the wrong variable

**Supply invariant not maintained elsewhere**
- Mint operation increments `total_supply` in some paths but not all (e.g., admin mint vs. user mint have different code paths)
- Rounding differences between per-wallet balances and total supply - systematic rounding causes total to drift from the sum of all wallet balances over time

**Missing TEP-74 getters**
- `get_jetton_data()` or `get_wallet_address()` getter absent or returning incorrect values - breaks integration with wallets, DEXes, and explorers
- Non-standard op codes for `transfer` (not `0xf8a7ea5`) or `burn` (not `0x595f07bc`) - breaks interoperability

## False Positives

- Custom burn mechanism that bypasses notification is authorized admin-only and `total_supply` is updated in the same transaction by the admin's direct call - verify the update is present
