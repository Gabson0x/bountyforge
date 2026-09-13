# Staking and Reward Security Patterns

> Applies to: token staking protocols, liquid staking, staking reward distributors, veToken staking, lockup staking, native SOL staking wrappers, validator delegation protocols, yield farming with lockups, any protocol that distributes rewards proportional to staked balances over time

## Protocol Context

Staking protocols on Solana track user share balances and distribute rewards through a per-share accumulator index pattern: a global index grows as rewards are deposited, and each user's pending reward is computed as `(global_index - user_snapshot_index) * user_shares`. The correctness of this model depends critically on the ordering of index updates relative to balance changes. Flash loan attacks against staking protocols exploit the ability to enter and exit a large staked position within a single transaction, claiming a disproportionate share of rewards that accrued during the stake window.

## Bug Classes

---

### Reward Accumulator Index Ordering (ref: fv-anc-11-cl6)

**Protocol-Specific Preconditions**

- `global_reward_index` updated in the same instruction that modifies user share balances, but after the balance modification
- User's pending rewards calculated using their new post-deposit or post-withdrawal balance rather than their balance at the time of accrual
- No atomic settle-before-mutate pattern enforced across all balance-modifying instructions

**Detection Heuristics**

- Trace the execution order in every instruction that modifies `user.shares`: find whether `accumulate_rewards(user)` or equivalent is called before or after `user.shares += delta`
- Check whether the global index is updated before the user's balance is changed, or whether the user's snapshot index is updated to the post-change global index in a way that skips owed rewards
- Verify with a test case: deposit at time T, harvest at T+1 with 0 elapsed accrual; user should receive 0 rewards for the deposit slot if index was correct at deposit time

**False Positives**

- Protocol settles pending rewards and updates the user's index snapshot as the very first operation in every balance-modifying instruction, before any state change
- Reward index is designed as a read-only observation point; balance changes never affect outstanding reward claims

---

### Flash Stake Reward Draining (ref: fv-anc-1-cl5, fv-anc-5-cl10)

**Protocol-Specific Preconditions**

- Deposit and withdraw instructions can be called in the same transaction with no minimum lock period
- Rewards that accrued before a large deposit can be claimed by the depositor if index ordering is wrong
- Flash loan provider on Solana enables borrowing large token amounts and repaying within the same transaction

**Detection Heuristics**

- Verify that a deposit immediately followed by a reward claim in the same slot cannot produce a non-zero reward payout
- Check whether a minimum staking duration (`min_stake_slots` or `min_stake_seconds`) is enforced before rewards can be claimed
- Identify whether the reward claim instruction can be called in the same transaction as a deposit without any intermediate slot boundary requirement
- Test: borrow X tokens, deposit X, claim rewards, withdraw X, repay X; verify net reward is zero or negative

**False Positives**

- Protocol enforces a minimum lockup before reward claims; the lockup period is enforced by the on-chain program not just by convention
- Reward index at deposit time is recorded as the user's baseline; any rewards claimed must have accrued after the deposit, making same-transaction flash stake yield zero

---

### Reward Dilution via Late Deposit

**Protocol-Specific Preconditions**

- Rewards are distributed proportionally at claim time rather than accrued continuously; a late depositor can enter just before a large reward distribution and claim a share
- Reward distribution instruction is publicly callable and can be front-run; an attacker can observe a large pending reward distribution and deposit just before it
- No snapshot mechanism that locks the eligible population at the start of a reward distribution period

**Detection Heuristics**

- Check whether reward distribution is a discrete event (transfer of a fixed amount) or a continuous accumulation; discrete events are more susceptible to front-running
- Verify whether rewards accrued before a user's deposit can be claimed by that user; the snapshot index recorded at deposit time should equal the current global index
- Look for reward distribution instructions that do not cap the eligible population at the start of the distribution

**False Positives**

- Continuous accumulator model correctly records the global index at deposit time and users can only claim rewards that accrued after their deposit
- Reward distribution uses a fixed-snapshot-eligible-users list rather than live balances; depositing after the snapshot has no effect

---

### Cooldown Period Bypass via Self-Transfer

**Protocol-Specific Preconditions**

- Staked balance can be transferred or delegated to a different address while the cooldown period is pending, allowing the recipient to bypass the cooldown
- Unstake and restake flow resets the cooldown; an attacker can unstake and immediately restake, keeping funds liquid while appearing staked for governance or reward purposes
- Cooldown timer stored per-user but not per-position; a single cooldown covers all pending withdrawals and can be reset by adding a new unstake

**Detection Heuristics**

- Check whether staked positions are transferable; if so, verify the cooldown timer travels with the position rather than being reset at the recipient
- Verify that a new unstake request does not reset or extend an existing cooldown timer in a way that benefits the unstaker
- Check whether restaking during cooldown is permitted; if so, verify the cooldown period resumes from where it left off, not from zero
- Look for any path that allows fund movement during the cooldown period that does not ultimately block the withdrawal until cooldown expires

**False Positives**

- Staked positions are not transferable; the owner at deposit time is the only address that can unstake
- Cooldown tracked per-lamport or per-deposit entry; each individual unstake request has its own cooldown timer that cannot be reset by other operations

---

### Precision Loss in Reward Computation

**Protocol-Specific Preconditions**

- Reward per share stored as a small integer without sufficient decimal scaling; rounding at each claim loses fractional rewards
- Users with small balances accrue zero rewards per slot due to truncation; over time, small stakers cannot accumulate meaningful rewards
- Fee deduction from rewards uses integer division that rounds against the staker below a threshold balance

**Detection Heuristics**

- Check the scaling factor for the per-share reward accumulator; common values are 1e9 or 1e18; verify it is sufficient for the expected reward rate and minimum stake amount
- Test with minimum stake amounts to confirm rewards accrue correctly over time without permanently rounding to zero
- Verify that accumulated precision loss across many epochs does not reach an amount that is economically significant for large stakers

**False Positives**

- Per-share reward accumulator uses 1e18 scaling factor and minimum stake is large enough that per-slot rewards are always non-zero
- Precision loss bounded to 1 unit per claim and documented as an intentional rounding choice favoring the protocol
