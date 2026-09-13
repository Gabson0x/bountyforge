# FV-SOL-6-C8 Return Bomb (Returndata Copy DoS)

## TLDR

When a contract makes an external call using `(bool success, bytes memory data) = target.call(payload)`, the EVM copies the full returndata into memory. A malicious or compromised `target` can return enormous amounts of data, causing the caller to spend enormous gas copying it - potentially exceeding the block gas limit and reverting the entire transaction.

This is particularly dangerous when `target` is user-supplied (e.g., in batch executors, meta-transaction relayers, or arbitrary call dispatchers).

## Detection Heuristics

- `(bool success, bytes memory returndata) = target.call(payload)` where `target` is user-controlled
- Batch executor or multicall copying returndata from arbitrary addresses
- `revert(add(returndata, 32), mload(returndata))` pattern propagating returndata from untrusted call
- Gas-limited calls where the gas budget doesn't account for returndata copy cost
- No `returndatasize()` check or cap before `returndatacopy`

## False Positives

- Returndata not copied: `(bool success,) = target.call(data)` (empty bytes pattern)
- Assembly call with explicit `outsize = 0`: `call(gas(), target, value, inOffset, inSize, 0, 0)` - no copy occurs
- Callee is hardcoded trusted contract (no user control over `target`)
- Gas-limited call with budget accounting for worst-case returndata size
- `returndatasize()` capped before copy: `if gt(returndatasize(), MAX_RETURN) { revert(0,0) }`
