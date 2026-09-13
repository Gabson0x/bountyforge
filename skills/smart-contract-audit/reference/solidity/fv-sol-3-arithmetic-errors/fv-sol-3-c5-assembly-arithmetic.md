# FV-SOL-3-C5 Assembly Arithmetic Silent Overflow and Division-by-Zero

## TLDR

Arithmetic inside `assembly {}` (Yul) does not benefit from Solidity 0.8's checked math. Overflow and underflow wrap silently (same as `unchecked {}`) and division by zero returns 0 instead of reverting. Developers accustomed to the Solidity 0.8 safety guarantees frequently introduce these bugs when writing inline assembly for gas optimization. Narrow-type arithmetic before upcast is a related Solidity-level issue: `uint8 a * uint8 b` overflows in the narrow type even though the result is assigned to a `uint256`.

## Detection Heuristics

**Assembly Division by Zero**
- `div(x, y)` or `sdiv(x, y)` inside `assembly {}` where denominator is user-supplied or not guaranteed non-zero
- No `if iszero(y) { revert(0, 0) }` guard before the division opcode
- Called in price, share, or ratio calculations where a zero denominator is a reachable state

**Assembly Overflow**
- `mul`, `add`, `sub` inside `assembly {}` without subsequent overflow check
- `mulmod` or `addmod` unused when wrapping-safe arithmetic is needed
- No `if gt(result, MAX)` guard after multiplication involving user-supplied values
- `add` used for pointer arithmetic without checking against `calldatasize()` or allocated memory bound

**Narrow-Type Overflow Before Upcast**
- Arithmetic on `uint8`, `uint16`, `uint32` operands before assignment to wider type
- Inside `unchecked {}` where Solidity 0.8 checked math is disabled
- Variables explicitly cast to narrow type as optimization: `uint8(x) * uint8(y)` before assigning to `uint256`

## False Positives

- Manual overflow checks in assembly present after each arithmetic op: `if gt(result, x) { revert(0, 0) }`
- Denominator checked with `require(denom > 0)` before entering the assembly block
- Assembly block is read-only (`mload`, `sload`, `calldataload` only, no arithmetic opcodes)
- Narrow-type operands explicitly upcast before operation: `uint256(a) * uint256(b)`
- `SafeCast` library used for all type conversions surrounding the block
- Mathematical proof of bounded operand range (e.g., both values `<= type(uint8).max / 2`)
