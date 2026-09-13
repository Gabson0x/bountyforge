# AMM and DEX Security Patterns (TON)

> Applies to: Dedust-style AMM protocols, STON.fi-style swap contracts, liquidity pool contracts on TON, swap routers, Jetton-based liquidity pools, any FunC or Tact contract implementing constant-product or curve-based invariant math, position managers, concentrated liquidity implementations

## Protocol Context

AMM and DEX contracts on TON operate under the async message model where every user action is a sequence of messages rather than an atomic transaction. This means slippage protection, deadline enforcement, and invariant verification must be explicitly applied at each hop of the message chain, not just at the entry point. Unlike EVM AMMs where a single transaction reverts atomically on slippage violation, a TON swap can span multiple contract calls, and a slippage check at the router level does not prevent the underlying pool from settling at a worse price if the router does not re-verify after the pool responds. Sandwich attacks on TON are constrained by the async model (true atomicity for the attacker is limited) but front-running is possible through mempool observation.

## Bug Classes

---

### Slippage Bypass

**Protocol-Specific Preconditions**

- `min_amount_out` computed from current pool reserves inside the pool contract at swap time rather than supplied by the user in the initiating message body
- No `min_amount_out` field in the swap message at all; protocol accepts any output amount
- Router contract checks slippage against the quoted amount, but the underlying pool is called directly via a message and processes the swap at the actual current reserves, which may have shifted

**Detection Heuristics**

- Find the swap message handler; check whether `min_amount_out` is a field in the message body parsed from the user's initiating message or computed on-chain at the pool
- Trace the message chain for a swap: if the slippage check is at the router and the pool receives a message without a minimum, the pool-level check is absent
- Verify that when slippage is violated (actual output < minimum), the pool sends a bounce-back message returning funds to the user, not a silent failure that credits 0 to the user
- Check whether the minimum is validated against the post-fee output or the pre-fee output; applying it pre-fee allows the fee to push the actual output below the minimum

**False Positives**

- Pool contract receives `min_amount_out` as part of its message payload and enforces it directly before crediting the output
- Router contract includes the user-supplied minimum in the forwarded pool message, not just its own slippage check

---

### Missing Swap Deadline

**Protocol-Specific Preconditions**

- Swap messages have no `valid_until` or `deadline` field in the message body
- TON message queues can delay message processing during network congestion; a user's swap can be held for minutes and executed at a significantly different price
- Governance or maintenance windows shift the effective exchange rate; a pending swap message submitted before the shift executes at the post-shift rate

**Detection Heuristics**

- Check the swap message body layout for a `deadline` or `valid_until` Unix timestamp field
- Find the swap handler's early validation section; verify `throw_unless(error::expired, now() <= deadline)` is called before any state modification
- For protocols using a two-phase swap (request + confirm), verify the deadline is enforced at the confirm phase as well, not only at the request phase
- Check whether the deadline is optional (defaulting to 0 meaning no expiry); a swap with deadline 0 should be rejected or treated as immediately expired

**False Positives**

- All swap messages include a deadline field and the handler rejects messages with `now() > deadline`
- Protocol is a CLMM or batch auction that settles at block-end with a deterministic settlement price; individual message timing does not affect the realized price

---

### AMM Invariant Not Verified After Swap

**Protocol-Specific Preconditions**

- After crediting the output token and debiting the input token from reserves, the protocol does not re-verify the constant product or curve invariant
- Partial fee accounting error causes `k = reserve_a * reserve_b` to decrease after a swap, allowing reserves to be depleted faster than the invariant permits
- LP removal in a single-sided mode does not verify that the remaining reserve ratio is within acceptable bounds

**Detection Heuristics**

- Find the post-swap state update; check whether `new_reserve_a * new_reserve_b >= old_reserve_a * old_reserve_b * (1 - fee_fraction)` is asserted
- For curve AMMs (Stableswap invariant), verify the invariant check uses the correct formula for the asset mix after each operation
- Check LP add and remove operations for invariant verification; single-sided additions or removals that skip the invariant check can drain one side of the pool
- Verify that fee accumulation does not double-count: fee should increase the effective k value, not reduce it

**False Positives**

- Invariant assertion present as a `throw_unless` immediately after reserve updates in both swap and LP operations
- Invariant stored and compared against the pre-operation value with a rounding tolerance that accounts for integer arithmetic

---

### Front-Running via Message Ordering

**Protocol-Specific Preconditions**

- TON mempool is observable before messages are included in a block; large swaps visible in the mempool can be front-run by a faster message from the same or a competing account
- TON validators can reorder messages within a block to extract MEV from large AMM swaps
- Protocol does not use a commit-reveal or delayed execution scheme for large trades

**Detection Heuristics**

- Assess whether any single swap is large enough relative to pool liquidity that front-running is economically viable given TON gas costs
- Check whether the protocol has any MEV protection such as a private relay, per-block randomized ordering, or a maximum allowed price impact parameter
- Verify that the slippage parameter enforced by the protocol is tight enough that front-running the swap beyond the tolerance is unprofitable

**False Positives**

- All swaps subject to a user-controlled slippage bound that is tight enough to make front-running economically unviable
- Protocol uses a batch auction settlement model where all orders in an epoch are settled at a single clearing price
