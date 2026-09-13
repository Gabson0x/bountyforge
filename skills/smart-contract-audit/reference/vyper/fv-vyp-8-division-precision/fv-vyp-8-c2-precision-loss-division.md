# FV-VYP-8-C2 Precision Loss in Division

## TLDR

Vyper performs integer division with truncation toward zero for `uint256` and `int256` types, and rounds toward negative infinity for `decimal`. Performing division before multiplication, or dividing small numerators by large denominators, silently discards the fractional remainder. This can result in zero fees, under-distributed rewards, or stale exchange rates.

## Detection Heuristics

**Division before multiplication**
- `(amount / denominator) * multiplier` where reversing the order to `(amount * multiplier) / denominator` would preserve precision
- Fee computed as `amount / 10000 * fee_bps` instead of `amount * fee_bps / 10000`, discarding up to `denominator - 1` units per operation

**Small numerator divided by large denominator producing zero**
- `fee = (amount * rate) / PRECISION` where `amount * rate` is smaller than `PRECISION` (e.g., `10**18`), always producing `0`
- Basis-point fee on small deposit amounts: `deposit * 3 / 10000` returns `0` for `deposit < 3334`

**Remainder silently discarded in distribution**
- `reward_per_participant = total_reward / len(self.participants)` with no accounting for `total_reward % len(self.participants)`, causing ETH or tokens to be permanently locked in the contract
- `per_epoch = total / epochs` where `total % epochs != 0` and no remainder accumulator exists

**`decimal` type division rounding not accounted for**
- Vyper `decimal` rounds toward negative infinity; `convert(a, decimal) / convert(b, decimal)` may round down in unexpected directions for negative intermediate values
- Mixed arithmetic between `uint256` and `decimal` via `convert` without awareness that `decimal` has 10 decimal places of precision, not 18

**Share price or exchange rate stored at low precision**
- `self.price_per_share = total_assets / total_shares` stored as `uint256` without a scaling factor, losing all fractional precision as the ratio approaches 1:1
- Accumulated interest computed as `principal * rate / 100` instead of using a higher-precision accumulator scaled by `10**18` or similar

## False Positives

- Division that intentionally floors the result where the remainder is either returned to the caller or accumulated in a separate `dust` variable
- Fixed-point arithmetic that scales the numerator before division (e.g., `amount * 10**18 / denominator`) and scales down the result afterward, correctly preserving precision
- `decimal` type used throughout with full awareness of its 10-decimal-place fixed-point semantics and no implicit conversion from `uint256`