# FV-SOL-1-C9 Transient Storage Reentrancy (EIP-1153)

## TLDR

Two reentrancy risks introduced by EIP-1153 (Cancun, March 2024): first, the classic `transfer()`/`send()` 2300-gas reentrancy guard is bypassed because `TSTORE` costs only 100 gas, allowing a `receive()` fallback to write transient state and re-enter within the gas limit. Second, a reentrancy lock backed by `TSTORE`/`TLOAD` that is never explicitly cleared persists for the entire transaction, causing permanent DoS for any multicall or flash-loan-callback flow that attempts a second call.

## Detection Heuristics

**2300-Gas Guard Bypass via TSTORE**
- `transfer()` or `send()` used as the sole reentrancy guard while the contract also contains `TSTORE`/`TLOAD` opcodes (inline assembly or via a transient-storage library)
- Contract deployed post-Cancun (block 19426587+) with comments or documentation assuming the 2300-gas limit prevents state modification in callbacks
- `receive()` or `fallback()` in any contract that interacts with the target contains `assembly { tstore(...) }` - executes at ~100 gas, well within 2300

**Transient Mutex Not Cleared**
- `assembly { tstore(LOCK_SLOT, 1) }` at function entry with no corresponding `assembly { tstore(LOCK_SLOT, 0) }` at exit
- Lock cleared only on the success path but not in revert paths - a failed inner call leaves the lock set for subsequent calls in the same transaction
- Multicall or flash-loan pattern where the lock is set in the first inner call and never released, causing all subsequent inner calls to revert

**Transient Storage Used for Security-Critical State**
- Transient variables used to track reentrancy guards, nonces, or access flags without accounting for within-transaction persistence across separate calls
- `tload` used to check a lock that was set in a different call frame earlier in the same transaction

## False Positives

- Reentrancy guard backed by regular storage slot (`SSTORE`/`SLOAD`) - 2300 gas limit remains effective for that guard
- Transient lock explicitly cleared in all exit paths including reverts (via assembly try/catch pattern or `ensure` cleanup blocks)
- CEI followed unconditionally - no external calls before state updates regardless of gas
