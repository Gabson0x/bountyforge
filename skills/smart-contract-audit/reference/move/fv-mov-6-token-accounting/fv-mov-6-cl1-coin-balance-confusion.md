# FV-MOV-6-CL1: Coin and Balance Accounting Confusion

## TLDR

Sui separates `Coin<T>` (an object with a UID, transferable) from `Balance<T>` (an internal primitive value without an object ID). Mixing these without consistent accounting creates ghost balances - coins exist on-chain with no internal tracking, or internal counters exceed actual coins held.

## Detection Heuristics

- Search for `coin::into_balance` and `coin::from_balance` conversion points - verify internal state is updated at every conversion
- Check whether the protocol ever reads its own `Coin<T>` balance using `coin::value` or `balance::value` on an internally held coin - if an external `coin::join` to the vault's coin changes its balance, reward calculations may be manipulable
- Verify vault accounting uses an internal `Balance<T>` field in a shared object, not the raw on-chain coin balance (which is manipulable by direct transfer)
- Trace `coin::split` calls - verify the sum of the two resulting coins equals the input; internal accounting must track both halves
- For protocols with multiple asset pools, check that `Balance<USDC>` cannot be credited to a `USDT` pool due to missing phantom type checks

## False Positives

- Clear separation enforced: `Balance<T>` for internal state, `Coin<T>` for user-facing I/O only
- `coin::into_balance` / `coin::from_balance` used consistently with no direct coin balance reads for business logic
- Invariant: sum of all internal `Balance<T>` equals actual on-chain token holdings, verified by tests
