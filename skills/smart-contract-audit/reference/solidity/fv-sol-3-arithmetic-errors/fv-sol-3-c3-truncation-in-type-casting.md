# FV-SOL-3-C3 Truncation in Type Casting

## TLDR

Downcasting from a wider integer type to a narrower one silently drops the high-order bits. Any value larger than the target type's maximum is truncated to its low-order bits, producing a different value with no revert or warning. This affects both explicit casts and implicit narrowing in storage assignments.

## Detection Heuristics

**Explicit Downcast Without Bounds Check**
- `uint8(x)`, `uint16(x)`, `uint32(x)`, `uint128(x)` where `x` is `uint256` or wider
- No preceding `require(x <= type(uintN).max)` before the cast
- Downcast result stored directly to state variable or emitted in event

**Return Value Downcast**
- External call return value cast to smaller type: `uint16(token.balanceOf(user))`
- Solidity ABI decoder target variable narrower than the ABI-declared return type
- `bytes32` to `address` cast where upper bytes may be non-zero

**Packed Struct / Storage Slot Truncation**
- Struct fields of mixed widths where a wider computed value is assigned to a narrower field
- Bit-shifting followed by narrowing cast: `uint8(x >> 8)` applied to potentially large `x`
- Storage packing via explicit cast in setter function without validation

**Intermediate Accumulator Overflow**
- Loop accumulating values into `uint32` or `uint64` variable where sum may exceed type max
- Fee or reward calculation result assigned to a `uint128` state variable without a cap check
- Price or rate derived from division stored in `uint96` without checking divisor constraint

## False Positives

- OpenZeppelin `SafeCast` library used: `SafeCast.toUint16(x)` reverts on truncation
- `require(x <= type(uintN).max)` or equivalent bound check immediately precedes the cast
- Value is produced by a modulo operation that guarantees it fits: `x % 256` cast to `uint8`
- Constant or literal value that provably fits the target type at compile time
- Compiler-level type constraint (e.g., function parameter already declared `uint16`) prevents wider input
