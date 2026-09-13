# FV-SOL-3-C2 Sign Extension

## TLDR

Sign extension issues occur when a smaller signed integer type is implicitly or explicitly cast to a larger signed integer type. The sign bit propagates to fill the additional high-order bits, which can turn a small negative value into a very large negative number or corrupt a value that was intended to be treated as unsigned.

## Detection Heuristics

**Signed-to-Wider-Signed Cast**
- `int8`, `int16`, or `int32` variable cast to `int256` or any wider signed type
- Cast occurs on a value that can be negative at runtime (no prior `require(x >= 0)`)
- Result used in multiplication, comparison, or storage without range validation

**Signed Value Used as Unsigned Index or Offset**
- `int` type cast to `uint` for use as array index, storage slot, or memory offset
- Pattern: `uint256(int8(userInput))` where `userInput` can be negative, producing a large `uint256`
- Negative value passed through ABI boundary and cast to unsigned type in receiving contract

**Bitwise Masking Absent After Cast**
- `int256(smallSignedVar)` used directly in bitwise operations without `& 0xFF` or equivalent mask
- Mixed signed/unsigned arithmetic where sign extension inflates a term: `uint256(int8(x)) * factor`
- Packed-encoding functions that cast signed fields to bytes without masking

**Cross-Contract ABI Mismatch**
- Callee function parameter is `int8`/`int16` but caller passes `int256` and truncates on return path
- ABI-encoded struct with signed fields decoded into wider types in a second contract

## False Positives

- Cast is from unsigned type (`uint8` to `uint256`): no sign bit exists, no extension
- Value is proven non-negative by a preceding `require(x >= 0)` or by its type constraints
- Explicit bitwise mask applied immediately after cast: `int256(x) & 0xFF`
- Operands explicitly upcast to `uint` before arithmetic: `uint256(uint8(x))` strips the sign
- Library (e.g., OpenZeppelin `SignedMath`) handles the conversion safely
