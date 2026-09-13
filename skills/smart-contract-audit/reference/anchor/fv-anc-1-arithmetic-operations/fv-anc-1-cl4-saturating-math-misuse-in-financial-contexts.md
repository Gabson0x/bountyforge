# FV-ANC-1-CL4 Saturating Math Misuse in Financial Contexts

## TLDR

Using `.saturating_add()` or `.saturating_sub()` in financial contexts silently caps values at `u64::MAX` or `0` instead of signaling an error. This masks real overflow or underflow conditions, leaving accounts with corrupted balances that are neither reverted nor flagged, and potentially allowing exploitation of the silent cap behavior.

## Detection Heuristics

**Saturating Ops on Balance or Amount Fields**
- `.saturating_add` or `.saturating_sub` applied to fields representing token amounts, share balances, fees, or reward totals
- No subsequent assertion that the result equals the uncapped mathematical value
- Financial accumulation loops using saturating ops to prevent panics rather than propagating an explicit overflow error

**Missing Error Path on Overflow**
- Arithmetic that should propagate `ErrorCode::Overflow` uses saturating math as a shortcut
- `.saturating_add` result assigned directly to an account field without checking `result == a + b` in debug mode or via invariant assertion
- `u64::MAX` value reachable in a balance field with no protocol invariant preventing it

**Comparison After Saturation**
- Comparison like `new_balance > old_balance` used as an overflow guard, where both operands could be `u64::MAX` due to prior saturation, making the check vacuous

## False Positives

- Saturating ops on non-financial counters such as event sequence numbers, retry counts, or epoch trackers where saturation is the documented intended behavior and not reachable via user input
- Contexts where the operand values are provably bounded below `u64::MAX` by earlier constraints, making saturation mathematically unreachable
