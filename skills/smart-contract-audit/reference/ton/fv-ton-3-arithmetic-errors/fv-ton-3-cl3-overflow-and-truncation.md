# FV-TON-3-CL3 Overflow and Truncation

## TLDR

While TVM 257-bit integer arithmetic throws on overflow by default, intermediate calculations involving `store_uint`/`load_uint` with smaller widths silently truncate, and unbounded accumulators can overflow before being packed.

## Detection Heuristics

**store_uint truncation on intermediate results**
- `store_uint(a * b, 64)` where the product of `a` and `b` can exceed 2^64 - the multiplication succeeds on the 257-bit TVM stack but truncates on pack
- Accumulator pattern: `total += amount` across many iterations where `total` is later packed with a fixed bit-width smaller than the accumulated range

**Multiplication before bounds checking**
- `int result = price * qty;` before any validation of `price` or `qty` - if either is user-controlled and large, the product overflows 257 bits (though rare given 257-bit size, it's possible with loop accumulation)
- No early rejection of zero-value or maximum-value inputs before entering arithmetic

**exit code collision**
- Custom `throw()` codes in range 0–127, reserved by TON for system exit codes - confuses error handling and debugging tooling
- Tact contracts using error codes 128–255, reserved by the Tact runtime

## False Positives

- Arithmetic result bounded by a protocol invariant (e.g., total supply cap, max deposit) that makes overflow mathematically impossible - document and verify the invariant
- `store_uint` width matches the type's actual range precisely and the compiler or prior check ensures no value exceeds it
