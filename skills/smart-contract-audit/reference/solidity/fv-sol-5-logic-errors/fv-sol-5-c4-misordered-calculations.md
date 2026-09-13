# FV-SOL-5-C4 Misordered Calculations

## TLDR

Arithmetic operations applied in the wrong sequence produce incorrect results. Common cases include applying a bonus before a tax so the bonus is also taxed, computing interest before updating the principal, or applying a percentage to a post-adjusted value when the specification requires it on the pre-adjusted amount.

## Detection Heuristics

**Bonus or Premium Applied Before Percentage Deduction**
- Bonus, incentive, or premium added to a base value before a tax or fee percentage is applied to the combined sum
- Specification states tax applies only to the principal, but code computes tax on `principal + bonus`
- Protocol fee deducted from `amount + reward` rather than from `amount` alone

**Incorrect Sequencing of Running Totals**
- Cumulative counter or running balance updated before a per-item calculation that should use the pre-update value
- Price impact or slippage applied before the fee deduction step rather than after
- Interest accrual computed on a balance that already includes the current period's deposit

**Compound Percentage Operations Applied Sequentially When Composition Is Required**
- Two successive percentage reductions applied as independent multiplications rather than as `(1 - r1) * (1 - r2)`
- Multiplication overflow possible because intermediate result exceeds type bounds before division
- Division performed before multiplication in a single expression, losing precision

## False Positives

- Order of operations explicitly matches the documented formula with a referenced specification
- Tax applied to base amount only; bonus added to the already-taxed result
- Unit tests verify boundary and midpoint values against expected formula output
