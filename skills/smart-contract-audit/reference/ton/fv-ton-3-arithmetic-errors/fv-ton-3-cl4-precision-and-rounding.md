# FV-TON-3-CL4 Precision and Rounding

## TLDR

Division performed before multiplication, rounding consistently in the user's favor, and precision loss in reward accumulators are systematic value-extraction vectors in TON DeFi contracts.

## Detection Heuristics

**Division before multiplication**
- `fee = amount / 100 * fee_rate` instead of `fee = amount * fee_rate / 100` - integer division truncates before the multiplication, losing up to `fee_rate - 1` units per call
- `shares = deposit / total_tokens * total_supply` instead of `shares = deposit * total_supply / total_tokens`

**Rounding direction favoring attacker**
- Deposit share calculation rounds UP (user gets more shares than their deposit warrants)
- Withdrawal token calculation rounds UP (user gets more tokens than their shares warrant)
- Both rounding in the user's favor enables round-trip profit: deposit → immediate withdraw → net gain

**Precision loss in reward accumulators**
- `reward_per_token += reward_amount / total_staked` with no precision multiplier - if `reward_amount < total_staked` the accumulator never increments, small stakers receive zero rewards forever
- Absence of a scaling factor (e.g., multiply numerator by `1_000_000_000` before dividing) in the accumulator update

**Division by zero**
- Divisor sourced from storage or message body without `throw_unless(error::zero_divisor, divisor > 0)`
- `total_supply` or `total_staked` can be zero on first deposit or after full withdrawal - pool calculations fail or produce infinity

## False Positives

- Rounding direction is intentional and documented, consistently rounds in protocol's favor (never user's favor for both directions simultaneously)
- Precision multiplier present but implemented as a named constant - verify the constant is applied
