# FV-SOL-4-C8 Arbitrary Storage Write

## TLDR

Two distinct patterns allow writing to arbitrary storage slots: inline assembly `sstore(slot, value)` where the slot is derived from user input without bounds checking, and in Solidity < 0.6, direct assignment to `array.length` combined with a crafted large index causes slot arithmetic to wrap, writing to any storage location. Both patterns allow an attacker to overwrite critical state variables including access control roles and ownership addresses.

## Detection Heuristics

**User-Controlled Assembly sstore**
- `sstore(slot, value)` in inline assembly where `slot` is derived from `msg.sender`, calldata, or any function parameter
- No allowlist or bounds check on the slot value before the assembly write
- Public or external function exposing direct assembly storage writes

**Pre-0.6 Array Length Manipulation**
- Solidity version `< 0.6` with `array.length =` assignment present anywhere in scope
- A `setLength(uint256)` or equivalent function sets an array length to an arbitrarily large value
- Subsequent indexed write `array[index] = value` with a large index wraps slot arithmetic to reach any storage slot

**Slot Collision via Proxy Patterns**
- Unstructured storage proxy where implementation slot selection depends on runtime input
- Storage slot for admin or implementation address reachable by writing to a colliding array or mapping slot

## False Positives

- Assembly is read-only (`sload` only, no `sstore` present)
- Slot is a compile-time constant (e.g., EIP-1967 literal `0x360894...`) with no user influence over its value
- Solidity >= 0.6 used throughout (compiler disallows `array.length` write assignment)
- `sstore` target slot derived exclusively from hardcoded internal constants, not from any external input
