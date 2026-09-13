# FV-SOL-3-C1 Overflow and Underflow

## TLDR

Integer overflow and underflow occur when arithmetic results exceed or drop below the bounds of the integer type. In Solidity versions before 0.8.0, these conditions wrap silently without reverting. In 0.8.0 and later, the compiler inserts checked arithmetic by default, but `unchecked {}` blocks and inline assembly restore the wrapping behavior.

## Detection Heuristics

**Pre-0.8.0 Contracts Without SafeMath**
- `pragma solidity ^0.7.x` or earlier with `+`, `-`, `*` applied to user-controlled values
- No `using SafeMath for uintN` declaration on contracts performing balance or supply arithmetic
- Arithmetic on `mapping` values (balances, allowances, shares) without overflow guards

**Unchecked Blocks in 0.8.0+ Contracts**
- `unchecked { x += amount; }` where `amount` is caller-supplied or unbounded
- `unchecked { balance -= withdrawal; }` without a prior `require(balance >= withdrawal)`
- Loop accumulators inside `unchecked {}` with no iteration bound enforced

**Multiplication Before Division Patterns**
- `a * b / c` where `a * b` can overflow before the division reduces the result
- Intermediate product assigned to same-width variable: `uint256 product = a * b` before `/ PRECISION`
- No `mulDiv` or equivalent full-precision multiplication used for fixed-point math

**Balance and Supply Accounting**
- Token mint/burn functions that add to or subtract from `totalSupply` without bounds
- Reward accumulation: `rewards[user] += rate * elapsed` where `rate * elapsed` is unbounded
- Share calculations: `shares * pricePerShare` with large values and no overflow check

## False Positives

- Solidity 0.8.0 or later compiler version used with no `unchecked {}` wrapping the arithmetic
- `unchecked {}` block where both operands are proven bounded (e.g., loop index `< 256` for a `uint8`)
- SafeMath library (`SafeMath.add`, `SafeMath.sub`, `SafeMath.mul`) applied to all operations on the affected variables
- Operands constrained by earlier `require` statements that cap values below overflow threshold
- Fixed-point multiplication using a verified `mulDiv` implementation that handles intermediate overflow
