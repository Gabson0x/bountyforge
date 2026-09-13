# FV-ANC-1-CL3 Arbitrary Rounding

## TLDR

Inconsistent or unintended rounding in fixed-point arithmetic causes cumulative loss or gain of funds. In Anchor programs handling token amounts or exchange rates, the choice of floor, ceiling, or round-to-nearest has protocol-level security implications.

## Detection Heuristics

**Unspecified Rounding Direction**
- Use of `.try_round_u64()` or equivalent generic rounding on collateral, fee, or reward calculations without documented rationale
- Rounding function selected based on convenience rather than the direction that protects the protocol

**Rounding Favoring the User in Protocol-Debit Paths**
- Fee calculations that round down, reducing the fee collected
- Debt repayment calculations that round down, allowing partial debt to persist indefinitely

**Rounding Favoring the Protocol in User-Credit Paths**
- Yield or reward distributions that round down when rounding up would be correct
- Redemption calculations that under-credit the user due to implicit floor rounding

**Mixed Rounding in Paired Operations**
- Deposit path uses ceiling, withdraw path uses floor, or vice versa, creating a rounding arbitrage
- Different rounding applied to numerator and denominator of the same ratio in separate instructions

## False Positives

- Rounding consistently applied in the direction that protects the protocol and is documented as a deliberate design decision
- Integer division where fractional tokens are provably immaterial due to token decimal precision
