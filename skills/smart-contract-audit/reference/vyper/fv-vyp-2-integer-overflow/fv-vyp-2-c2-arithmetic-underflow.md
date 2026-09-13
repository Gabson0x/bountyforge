# FV-VYP-2-C2 Arithmetic Underflow

## TLDR

Underflow on unsigned integer types in Vyper wraps to the maximum value of the type when the result would be negative. Unlike Solidity with SafeMath or Vyper 0.3.8+ defaults, older compiler versions and explicit `unchecked` blocks do not revert on underflow, enabling an attacker to inflate balances or bypass balance checks by triggering a wrap.

## Detection Heuristics

**Subtraction on `uint256` without a preceding lower-bound assertion**
- `self.balances[msg.sender] -= amount` with no `assert self.balances[msg.sender] >= amount` before it
- `self.total_supply -= burned` without verifying `burned <= self.total_supply`
- Loop body performs `running_total -= fee` where `fee` is caller-controlled and `running_total` may be smaller than `fee`

**`convert` widening after subtraction**
- Subtraction performed on a narrower type (e.g., `uint128`) and then `convert`-ed to `uint256`, propagating a wrapped value silently

**Subtraction result stored in intermediate local variable before check**
- `result: uint256 = a - b` assigned without assertion, then `result` used in a later condition that assumes non-negative semantics
- A function returns `a - b` directly as a `uint256` return value with no guard

**Compiler pragma older than 0.3.8**
- `# @version ^0.2` or `# @version ^0.3.0` through `^0.3.7` where underflow is not guaranteed to revert

## False Positives

- Vyper 0.3.8+ compiled code in default mode where the compiler inserts underflow checks unconditionally
- Subtraction preceded immediately by `assert a >= b` or an equivalent conditional that reverts on failure
- Subtraction result bounded by design: e.g., decrementing a loop counter initialized from `len(arr)` where the loop structure prevents the counter from going below zero