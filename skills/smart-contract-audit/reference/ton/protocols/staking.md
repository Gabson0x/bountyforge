# Staking and Reward Security Patterns (TON)

> Applies to: TON nominator pool contracts, validator delegation protocols, liquid staking on TON, Jetton-based staking reward distributors, TON Whales staking, tsTON, hTON, any FunC or Tact contract distributing rewards proportional to staked balances over time

## Protocol Context

Staking on TON has two distinct layers: native TON validator staking (nominator contracts delegating to validators) and application-layer Jetton staking (user deposits Jettons and earns yield). Both layers share common accumulator-ordering vulnerabilities but the validator layer adds TON-specific risks around commission manipulation and validator key management. Application-layer staking contracts on TON are particularly vulnerable to direct Jetton transfer inflation of reward rates, since any address can send Jetton tokens to any contract without using the staking deposit op-code, potentially diluting or inflating the reward pool.

## Bug Classes

---

### Reward Accumulator Ordering

**Protocol-Specific Preconditions**

- Global `reward_per_token` accumulator updated in the same message handler that modifies a user's staked balance, but after the balance modification
- User's pending reward computed as `(current_reward_per_token - user_reward_per_token_snapshot) * user_balance`; if the snapshot is updated after the balance change, the new balance is used retroactively
- Staking contract processes unstake and reward claim in the same message handler without settling pending rewards first

**Detection Heuristics**

- Trace the execution order in every op-code handler that modifies `user_balance`: verify `settle_pending_rewards(user)` and accumulator update appear before any balance change
- Check the order of storage writes: `set_reward_per_token(new_accumulator)` must precede `set_user_balance(new_balance)` and `set_user_snapshot(new_accumulator)` in the same handler
- Verify with a test scenario: stake, wait for rewards to accrue, stake again in a new message, immediately claim; user should earn rewards only on the first stake amount for the pre-second-stake period
- Check multi-reward-token systems: each token must have an independent accumulator and each must be settled before any balance change

**False Positives**

- Every balance-modifying handler settles rewards as its first operation before any state mutation
- Accumulator is a read-only observation point; rewards are credited to a separate pending balance that is computed at claim time from a snapshot taken at the last balance change

---

### Flash Stake Reward Capture

**Protocol-Specific Preconditions**

- No minimum staking duration; user can stake and unstake in back-to-back messages sent in the same logical transaction chain
- Reward distribution is a discrete snapshot event (all rewards distributed to current stakers at a point in time) rather than continuous accumulation; attacker can stake just before the snapshot
- No warmup period between stake and reward eligibility

**Detection Heuristics**

- Check whether the staking contract enforces a minimum lock period: `throw_unless(error::locked, now() - stake_time >= MIN_LOCK_SECONDS)` before allowing unstake
- Identify whether reward distribution is event-driven or continuous; discrete events are snapshot-able and more susceptible to last-second staking
- For continuous accumulators, verify that a same-block stake and unstake yields zero net reward (the accumulator value at deposit equals the accumulator value at withdrawal)
- Check whether the unstake message can be sent in the same message chain as the stake message, effectively bypassing any block-boundary checks

**False Positives**

- Minimum lock period enforced on-chain, not just by convention; verified by checking the on-chain unstake handler for a time check
- Continuous accumulator correctly records the global index at stake time; same-block unstake yields zero reward by construction

---

### Reward Rate Inflation via Direct Transfer

**Protocol-Specific Preconditions**

- Reward rate derived from the staking contract's Jetton balance rather than from an internal tracked `reward_reserve` variable
- Attacker sends a large Jetton transfer directly to the staking contract's Jetton wallet address without using the `op::add_rewards` op-code
- The extra balance inflates the apparent reward pool, diluting per-staker rewards; or it deflates the reward rate if the contract computes rate as `reward_reserve / total_staked` and the denominator grows

**Detection Heuristics**

- Find the reward rate calculation; check whether it reads the Jetton wallet balance or a tracked internal variable
- Verify the `op::jetton_transfer_notification` handler (or equivalent) for unsolicited transfers: does the contract accept them silently and add them to the reward pool, or does it reject/bounce transfers from unknown senders?
- Check whether the total reward pool is bounded: can an attacker donate tokens to change the reward rate or dilute existing reward obligations?
- For emission-based rewards (fixed tokens per time period), verify the emission logic does not incorporate the contract's live Jetton balance

**False Positives**

- Reward reserve tracked in a persistent variable updated only through the privileged `op::add_rewards` handler; Jetton balance is irrelevant to reward calculations
- Unsolicited Jetton transfers are bounced back or credited to a separate dust account that does not affect the reward pool

---

### Cooldown Griefing via Dust Messages

**Protocol-Specific Preconditions**

- Cooldown period for unstaking can be reset by a new stake or partial unstake from the same or a different address
- Attacker sends a dust stake message to the victim's staking position, triggering a cooldown reset for the victim's pending unstake
- No per-epoch or per-deposit entry cooldown tracking; a single contract-level or user-level cooldown applies to all pending unstakes and is reset by any deposit activity

**Detection Heuristics**

- Check the cooldown reset logic: what events reset `cooldown_start_time` in the user's data? Any new stake? Any external trigger?
- Verify whether a dust stake (minimum TON value stake) is sufficient to trigger a cooldown reset; if so, the attack is economically trivial
- Check whether the cooldown is per-deposit-entry (each unstake request has its own timer) or per-user (a single timer covers all pending unstakes)
- Verify that third parties cannot trigger cooldown resets for another user's staking position

**False Positives**

- Cooldown is tracked per unstake request entry, not per user; a new stake does not affect pending unstake cooldown timers
- Minimum stake amount is large enough to make repeated griefing economically unviable relative to the gas cost
