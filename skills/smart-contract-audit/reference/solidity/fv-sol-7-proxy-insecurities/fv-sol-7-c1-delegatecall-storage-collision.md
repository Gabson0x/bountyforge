# FV-SOL-7-C1 delegatecall Storage Collision

## TLDR

`delegatecall` executes code from another contract in the calling contract's storage context, preserving `msg.sender` and `msg.value`. When the proxy and implementation contracts declare state variables at overlapping storage slots, writes from the implementation silently corrupt proxy-level state such as the admin address or the stored implementation pointer.

## Detection Heuristics

**Proxy and Implementation Share Sequential Slot Layout**
- Proxy declares one or more state variables (e.g., `address public implementation`) starting at slot 0
- Implementation also declares state variables starting at slot 0
- No EIP-1967 or EIP-7201 namespaced slot used for proxy-reserved storage

**Implementation Pointer Stored in Sequential Slot**
- `implementation` address stored as a regular top-level state variable instead of via `sstore` to a `keccak256`-derived slot
- First storage slot of proxy holds the implementation address, making it overwritable by any implementation function that writes to slot 0

**User-Controlled delegatecall Target**
- `delegatecall` called with a target address supplied by the caller or stored in unconstrained proxy state
- No validation that the target address is an approved or expected implementation contract

**Missing Zero-Address Guard Before delegatecall**
- Fallback or forwarding function calls `delegatecall` without checking `implementation != address(0)`
- Uninitialized proxy delegates to the zero address, which succeeds silently on some chains

## False Positives

- Implementation pointer stored via `sstore` at a `keccak256`-derived slot (EIP-1967: `keccak256("eip1967.proxy.implementation") - 1`)
- All proxy-reserved storage uses EIP-7201 namespaced positions with no overlap with sequential implementation slots
- Implementation contract has no state variables at slot 0 (all storage in a diamond-style namespaced struct)
- Read-only proxies that never write storage through delegatecall
