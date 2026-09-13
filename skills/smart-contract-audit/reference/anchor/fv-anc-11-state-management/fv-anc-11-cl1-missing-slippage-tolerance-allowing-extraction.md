# FV-ANC-11-CL1 Missing Slippage Tolerance Allowing Extraction

## TLDR

Instructions that perform token swaps, liquidity operations, or price-sensitive conversions without a caller-supplied minimum output amount allow extractors to sandwich the transaction. On Solana, MEV via Jito bundles means any public transaction with zero slippage protection is a reliable extraction target for atomic sandwich attacks within the same block.

## Detection Heuristics

**Zero or Derived Minimum Output**
- Swap or liquidity instruction accepts `min_amount_out: 0` or `minimum_tokens: 0` without rejecting it
- Minimum output computed inside the instruction from the current pool state rather than passed as a caller parameter; attacker can move pool state before and after
- Automated keeper or harvest instruction executes a swap with no user-supplied slippage bound; keeper code defaults to 0 or computes from on-chain price in the same transaction

**No Deadline Enforcement**
- Transaction does not include a `deadline` or `valid_until_slot` parameter that the program checks against `Clock.slot` or `Clock.unix_timestamp`
- Swap instruction can be delayed or reordered by a Jito bundle leader without any time-bound expiry

**Slippage Applied Only Partially**
- Slippage bound enforced on one leg of a two-leg swap but not on the intermediate or final leg
- Protocol-level slippage check occurs after fees are deducted, allowing the post-fee amount to fall below the pre-fee minimum without triggering the revert

## False Positives

- Instruction is callable only by a trusted relayer that routes through a private Jito bundle with MEV rebate; mempool visibility is zero
- Slippage bound is enforced at a higher aggregator layer that validates output before forwarding to the protocol instruction
- Operation is a withdrawal of an exact token amount with no price-sensitive conversion; slippage concept does not apply
