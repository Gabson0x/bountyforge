# FV-VYP-2-C1 Arithmetic Overflow

## TLDR

In Vyper 0.3.x and earlier, arithmetic on integer types does not revert on overflow by default in all compilation modes. In Vyper 0.4.x the behavior changed, but code compiled with older compiler versions or with `@pragma optimize` can silently wrap. Overflow in token minting, share accounting, or fee accumulation leads to incorrect balances or supply values.

## Detection Heuristics

**Unchecked additive accumulation on `uint256` storage variables**
- `self.total_supply += amount` with no prior assertion that `self.total_supply + amount <= MAX_SUPPLY` or similar bound
- `self.balances[to] += amount` without verifying the sum does not exceed a declared cap
- Repeated additions in a loop (e.g., reward accumulation) with no overflow guard on the running total

**`convert` narrowing before arithmetic**
- `convert(value, uint128)` applied to a `uint256` before addition or multiplication, silently truncating the high bits before the operation
- `convert(a, int256)` used on an unsigned accumulator then added to a signed value, allowing wrap-through negative

**Multiplication before bounds check**
- `shares * price_per_share` computed without verifying neither operand is large enough to overflow before the multiplication
- `amount * 10**18` with `amount` accepted directly from `msg.value` or calldata without a cap

**Compiler version below 0.3.8 with no explicit safe-math annotations**
- `# @version ^0.2` or `# @version ^0.3.0` in the pragma where overflow checking was not unconditionally enabled
- No `MAX_*` constant and no `assert` bracketing any additive or multiplicative operation on accumulator variables

## False Positives

- Code compiled with Vyper 0.3.8+ where the compiler unconditionally inserts overflow checks for all integer operations in the default (non-`unchecked`) context
- Arithmetic bounded by a `constant` cap asserted before the operation: `assert self.total_supply + amount <= MAX_SUPPLY`
- Values derived from `len()` on a `DynArray` with a declared maximum, making overflow geometrically impossible within the type range