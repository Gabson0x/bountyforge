# FV-SOL-3-C6 Assembly Memory and Calldata Pitfalls

## TLDR

Inline assembly bypasses Solidity's memory safety guarantees. Six distinct pitfalls arise from incorrect memory layout assumptions, dirty bits, scratch space reuse, and calldata boundary handling. Each manifests as silent data corruption rather than a revert.

- `mstore8` dirty bytes: writing a single byte leaves 31 dirty bytes in the surrounding word
- Scratch space corruption: Solidity overwrites `0x00-0x3f` between assembly blocks
- Dirty higher-order bits: loading sub-256-bit values without masking
- `returndatasize` as zero substitute: nonzero after any preceding external call
- `calldataload` out-of-bounds: reads zero-padded bytes silently past `calldatasize()`
- Free memory pointer corruption: writing above `mload(0x40)` without updating it

## Detection Heuristics

**mstore8 Partial Write**
- `mstore8` in a loop building a byte array, followed by `keccak256` or `return` on the full word region
- Slot not zeroed with `mstore(ptr, 0)` before byte-level writes
- `mload` used to read a word containing `mstore8`-written bytes with uninitialized neighbors

**Scratch Space Corruption**
- `mstore(0x00, ...)` or `mstore(0x20, ...)` in one assembly block, with Solidity statements in between, then `mload` in a later assembly block
- Intervening `keccak256(a, b)`, `abi.encode`, or any memory allocation can clobber `0x00-0x3f`

**Dirty Higher-Order Bits**
- `calldataload`, `sload`, or `mload` into a variable used as `address`, `uint128`, `uint8`, or `bool` without bitmask
- Comparison `if eq(addr, target)` where `addr` is not masked to 20 bytes
- `mapping[addr]` lookup where `addr` has dirty upper bits, producing the wrong storage slot

**returndatasize as Zero**
- `let ptr := returndatasize()` or `mstore(returndatasize(), x)` appearing after any `call` or `staticcall`
- Intended optimization of using `returndatasize()` as a cheaper `0` is only valid before any external call in the same execution context

**calldataload Out-of-Bounds**
- `calldataload(offset)` where offset is user-controlled or derived from user input without a bound check
- No `require(calldatasize() >= minSize)` before the assembly block
- Index multiplication: `add(base, mul(index, 32))` without `require(index < maxCount)`

**Free Memory Pointer Corruption**
- `mstore` at `mload(0x40)` without a subsequent `mstore(0x40, newPtr)` updating the free pointer
- Assembly block writes to arbitrary offsets with no pointer update
- Data overwritten by the next Solidity-level memory allocation after the block

## False Positives

- Only scratch space (`0x00-0x3f`) used, and all reads occur within the same contiguous assembly block
- `mload(0x40)` read, data written above it, and pointer updated: `mstore(0x40, add(ptr, size))`
- Block annotated `/// @solidity memory-safe-assembly` and verifiably compliant with the Solidity memory model
- Dirty bit concern does not apply: value produced by a prior Solidity expression that already cleaned the high-order bits
- `returndatasize()` used before any external call in the same execution context
- Calldataload offset is static and fixed-size with a compiler-generated ABI decoder handling bounds
