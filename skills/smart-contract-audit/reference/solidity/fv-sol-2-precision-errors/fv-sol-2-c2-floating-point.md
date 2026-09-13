# FV-SOL-2-C2 Floating Point

## TLDR

Solidity has no native floating-point type. Contracts that perform division before multiplication on integer values silently truncate fractional parts, producing results that are systematically wrong - often rounding small values to zero entirely. The error compounds across repeated calculations and is especially damaging in reward distribution, interest accrual, and price computation where many small fractions must sum correctly.

## Detection Heuristics

**Division Before Multiplication**
- Expression pattern `(a / b) * c` where `a`, `b`, `c` are `uint256` - the division truncates before the multiplication can recover precision
- Intermediate variable stores `a / b` and that variable is later multiplied by another value
- Reward or interest formula written as `rate / DENOMINATOR * principal` rather than `rate * principal / DENOMINATOR`

**Scaling Factor Absent**
- No WAD (`1e18`), RAY (`1e27`), or equivalent scaling constant applied before division in financial formulas
- Percentage or ratio computed as `numerator / denominator` with no preceding multiplication by a precision constant
- Library like PRBMath, FixedPointMathLib, or ABDKMath64x64 not imported despite fractional arithmetic being present

**Small Value Truncation to Zero**
- `(userHoldings / totalHoldings) * reward` where `userHoldings < totalHoldings` - result is zero for minority holders
- Fee calculated as `amount * basisPoints / 10000` where `amount` may be small enough that `amount * basisPoints < 10000`
- Compound interest accumulator updated as `principal * rate / 1e18` where `principal * rate` underflows the denominator

## False Positives

- Multiplication is always performed before division: `a * c / b` pattern is consistent throughout the codebase
- A fixed-point math library (PRBMath, FixedPointMathLib, DSMath) handles all fractional arithmetic
- Values are guaranteed by protocol invariants to be large enough that truncation loss is bounded, documented, and acceptable (e.g., dust below 1 wei per operation)
