# AMM and DEX Security Patterns

> Applies to: AMM protocols, DEX swap protocols, constant product market makers, concentrated liquidity managers, token swap pools, liquidity provisioning protocols, arbitrage-exposed swap routers, any protocol with on-chain price-setting swap mechanics on Solana

## Protocol Context

AMM protocols on Solana are exposed to the same structural MEV dynamics as EVM DEXes, with the added dimension of Jito bundle ordering that enables atomic sandwich attacks in a single block. Every state-changing operation that involves a price-sensitive output visible in the public mempool is a candidate for front-running or sandwiching. Solana's lack of a native mempool reduces some MEV vectors but Jito bundles provide equivalent ordering control for attackers. Pool reserve ratios are manipulable within a single transaction, making any spot-price consumption that does not use a TWAP vulnerable to flash manipulation.

## Bug Classes

---

### Missing Slippage Protection (ref: fv-anc-11-cl1)

**Protocol-Specific Preconditions**

- Swap or liquidity instruction accepts `min_amount_out: 0` without rejecting it
- Minimum output computed on-chain from pool state rather than passed as a caller parameter; attacker has already moved the pool before the instruction executes
- Automated keeper or harvest path calls a swap with no slippage bound; keeper uses a zero minimum for convenience

**Detection Heuristics**

- Search for all swap instruction call sites for `min_amount_out: 0`, `minimum_tokens_out: 0`, or equivalent fields set to zero
- Verify that slippage parameters are caller-supplied and not derived from on-chain pool state in the same instruction
- Check automated compound, harvest, or rebalance functions for hardcoded zero minimums or on-chain derived minimums
- Confirm that `deadline` or `valid_until_slot` is also accepted and enforced, not just the minimum output

**False Positives**

- Instruction is only callable by a trusted keeper operating via Jito private bundles; no public mempool exposure
- Slippage enforcement is at the aggregator router layer before funds reach the swap pool; the pool itself does not need to enforce it

---

### Pool Reserve Manipulation via Flash Swap

**Protocol-Specific Preconditions**

- Protocol derives a price or exchange rate from pool reserves at instruction time rather than from a TWAP
- Flash loan or flash swap allows large-scale temporary reserve changes within a single transaction
- No minimum time between consecutive swaps in the same pool; rapid manipulation and reversal in one transaction is possible

**Detection Heuristics**

- Identify all price or exchange rate derivation sites; check whether they read live pool reserves or use a TWAP oracle account
- Verify that protocols using pool-derived prices have a TWAP with a sufficiently long window relative to the block time
- Check whether flash swaps within the protocol itself allow borrowing pool reserves and repaying within one instruction set, without a price impact protection mechanism

**False Positives**

- Protocol uses the Raydium or Orca TWAP oracle account, not spot reserves; single-block manipulation cannot meaningfully move the time-weighted average
- Protocol applies a maximum price deviation check against a stored reference price that prevents execution at manipulated prices

---

### Same-Asset Swap Enabling Rounding Profit

**Protocol-Specific Preconditions**

- Protocol allows swapping the same token on both sides of a pair; swap of token A for token A with any fee structure should yield zero or negative output
- Rounding in the swap computation produces a positive output for a same-asset swap due to precision gaps in fee deduction
- No explicit check that input token mint differs from output token mint before the swap

**Detection Heuristics**

- Check the swap instruction for a `require!(input_mint != output_mint)` assertion
- Test a swap of token A for token A; verify the output is always less than or equal to input after fees
- Examine the fee computation path; confirm that same-asset fee application cannot produce a net positive output via rounding

**False Positives**

- Protocol explicitly asserts `input_mint != output_mint` as the first check in the swap instruction
- Pool architecture makes same-asset swaps architecturally impossible; each pool handles exactly two distinct mints

---

### Liquidity Provider Position Manipulation

**Protocol-Specific Preconditions**

- LP token mint and burn not guarded against race conditions in a multi-instruction transaction; two simultaneous operations can observe stale total supply
- LP position value calculation uses spot reserves that can be manipulated before or after the LP operation
- Remove liquidity operation applies slippage protection only on the total output, not on each individual token output; imbalanced removal exploitable

**Detection Heuristics**

- Verify that LP mint and burn operations read pool reserves in the same instruction where the LP tokens are issued or burned, with no intermediate state
- Check that `remove_liquidity` enforces minimum amounts on both token outputs independently, not just on a combined USD value
- Identify whether LP position valuation for collateral or governance uses live pool reserves or a time-averaged calculation

**False Positives**

- Protocol uses a locked reserve snapshot taken at the start of each LP operation; intermediate state changes do not affect the snapshot
- LP token mint is controlled by a PDA that enforces sequential ordering; concurrent mints are serialized

---

### Fee Accounting Invariant Violations

**Protocol-Specific Preconditions**

- Swap fees accumulated in the pool account are tracked in a separate field from the trading reserves; desynchronization between the two allows fee theft
- Fee withdrawal does not verify that the remaining balance maintains the pool invariant (k value)
- Fee computation rounds down in a direction that benefits the swapper rather than the pool, allowing systematic extraction of protocol revenue

**Detection Heuristics**

- Find the fee accumulation and fee withdrawal paths; verify that fee balances are tracked consistently with pool reserves
- Check that the invariant (constant product or otherwise) still holds after a fee withdrawal from the pool
- Verify the rounding direction in fee computation: fees charged to swappers should round up (favor protocol), not down

**False Positives**

- Protocol maintains a separate fee vault account distinct from trading reserves; fee withdrawal from the fee vault does not touch trading reserves
- Invariant check is applied after every state-modifying operation including fee withdrawals
