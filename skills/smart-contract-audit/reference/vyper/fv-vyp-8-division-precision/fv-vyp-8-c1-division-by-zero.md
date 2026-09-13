# FV-VYP-8-C1 Division by Zero

## TLDR

Vyper reverts on division by zero for integer types, but the revert is an unhandled exception that may occur at unexpected points in execution, leaving state partially modified if writes preceded the division. Contracts must validate divisors before any division that depends on runtime values.

## Detection Heuristics

**Division by a value derived from storage without a prior zero-check**
- `total_amount / self.total_shares` where `self.total_shares` can be zero if no participants have joined yet
- `reward / len(self.participants)` where `self.participants` is a `DynArray` that may be empty at the time of the call
- `(value * 100) / self.total` where `self.total` starts at zero before the first deposit

**Division by a function parameter without validation**
- `return amount / participants` in a `@view` or `@pure` function where `participants` is a caller-supplied argument with no `assert participants > 0` guard
- `fee = (msg.value * rate) / denominator` where `denominator` is passed by the caller

**State mutations before the division that are not rolled back on revert**
- Storage variable updated (e.g., a counter incremented or a balance modified) before a division operation that may revert, leaving the contract in an inconsistent state if the division panics

**Share or ratio calculations on first-deposit edge cases**
- Initial liquidity deposit to a pool computes `shares = deposited_amount / self.price_per_share` where `self.price_per_share` is initialized to zero or only set after the first deposit
- `convert(a, decimal) / convert(b, decimal)` where `b` as a `decimal` can be `0.0`

## False Positives

- Division by a `constant` value defined at the module level, which the compiler can verify is non-zero at compile time
- Division preceded by `assert denominator > 0` or an equivalent `if denominator == 0: return 0` guard that handles the zero case before the operation
- Division by `len(arr)` where `arr` is a `DynArray` that is always non-empty due to a prior `assert len(arr) > 0` or an invariant maintained by the contract