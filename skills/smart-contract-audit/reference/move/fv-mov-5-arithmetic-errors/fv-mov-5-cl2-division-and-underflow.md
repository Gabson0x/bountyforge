# FV-MOV-5-CL2: Division Before Multiplication, Division by Zero, Underflow

## TLDR

Move has no floating-point types. Early division truncates precision: `(amount / total) * price` can round to zero for small amounts, enabling dust exploits. Division by zero causes an abort, which can permanently DoS critical operations. Subtraction without a bounds check aborts on underflow in debug, wraps in release.

## Detection Heuristics

- Search for division operators (`/`) and check whether they appear before any multiplication in the same expression
- Safe pattern: multiply first - `(amount * price) / total` - use u128 intermediates for u64 inputs to prevent overflow
- For any divisor that can reach zero (total supply, pool balance, total shares), verify an explicit `assert!(divisor > 0)` or early return
- Empty pool scenarios are high-risk: `total_supply == 0` is valid state in many protocols at launch or after full withdrawal
- Search for subtraction expressions involving user balances, collected fees, or pool reserves - trace whether the left side can be less than the right side under any input combination

## False Positives

- Multiply-before-divide pattern used consistently
- Zero divisor guard present: `assert!(total_supply > 0, EZeroSupply)` or equivalent
- Checked subtraction: `assert!(a >= b)` before `a - b`
- Saturating or checked math library handles all edge cases
