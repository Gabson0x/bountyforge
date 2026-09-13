# Staking and Reward Security Patterns (Sui/Move)

> Applies to: Aftermath liquid staking, Volo liquid staking, SuiFrens staking, Sui validator staking wrappers, Move-based reward distribution modules, veToken staking, any Move module issuing staking receipts or distributing rewards proportional to staked balances on Sui

## Protocol Context

Staking protocols on Sui use Move's object model for staking receipts: a user's staked position is typically a non-fungible owned object (a `StakeReceipt` or `WrappedStakePosition`) rather than a fungible balance. This owned-object model makes most staking operations user-gated (only the receipt owner can unstake), but introduces shared-object dependency for global accumulator state (total staked, reward index). The hot-potato flash loan pattern on Sui enables flash staking: borrow SUI, deposit, receive a receipt, claim rewards, unstake, repay - all within one PTB. A correctly implemented continuous accumulator makes flash staking yield zero reward by construction; protocols with discrete reward distribution events are more vulnerable.

## Bug Classes

---

### Reward Accumulator Ordering

**Protocol-Specific Preconditions**

- Global `reward_per_token` accumulator updated in the same function that modifies a user's staked balance, but after the balance modification
- `pending_rewards = (current_reward_per_token - user_snapshot) * user_balance` computed with `user_balance` already reflecting the new deposit or withdrawal
- Move's object mutation model: the user's receipt object is modified before the global accumulator is updated, causing the snapshot to be recorded against the new balance

**Detection Heuristics**

- Trace every Move function that calls both `update_balance(receipt, delta)` and `update_accumulator(pool)`; verify the accumulator update precedes the balance update
- The safe pattern in Move: (1) update `pool.reward_per_token`, (2) settle `pending = (pool.reward_per_token - receipt.snapshot) * receipt.balance`, (3) add to `receipt.unclaimed`, (4) update `receipt.snapshot = pool.reward_per_token`, (5) update `receipt.balance`
- Check multi-reward-token systems: each reward token requires its own accumulator; verify all accumulators are settled before any balance change
- Test: stake 100 units, wait for reward accumulation, stake 100 more units, immediately claim; verify reward is only for the first 100 units for the pre-second-stake period

**False Positives**

- `settle_rewards(receipt, pool)` is the first call in every balance-modifying function; enforced as a wrapper pattern at every entry point
- Rewards computed from a snapshot taken at the previous balance change, not from the current accumulator; new balance cannot retroactively earn historical rewards

---

### Flash Stake via PTB

**Protocol-Specific Preconditions**

- Deposit and withdraw can be called in the same PTB with no minimum lock enforced on-chain
- Discrete reward distribution event (not continuous accumulator): large deposit just before the distribution captures a proportional share of the reward
- PTB allows: borrow SUI flash loan, deposit, receive receipt, trigger reward distribution, redeem receipt, repay flash loan - all in one atomic transaction block

**Detection Heuristics**

- Check whether the staking module enforces a minimum lock period: `assert!(clock::timestamp_ms(clock) >= receipt.stake_time_ms + MIN_LOCK_MS, ERROR_LOCKED)`
- Identify whether reward distribution is event-driven or continuous; continuous accumulators correctly yield zero reward for a same-block stake and unstake
- For discrete distribution, verify the snapshot of eligible stakers is taken before the distribution transaction is executable; the snapshot cannot include stakers who deposit in the same transaction
- Check whether deposit and unstake can both appear in a single PTB; if so, verify the minimum lock check is applied at unstake time against `receipt.stake_time_ms`

**False Positives**

- Minimum lock period enforced in the unstake function against the receipt's recorded stake timestamp
- Continuous accumulator with correct ordering makes same-block stake and unstake yield zero net reward by design

---

### Liquid Staking Receipt Duplication

**Protocol-Specific Preconditions**

- Liquid staking protocol issues a `LiquidStakeReceipt` object representing the staked amount; a bug in the receipt issuance or transfer path allows the same underlying stake to back multiple receipts
- Receipt is split or merged via a poorly validated operation that creates more total receipt value than the underlying stake
- Redemption function validates receipt by type but not by total supply cap; unlimited redemptions possible if receipts can be freely minted

**Detection Heuristics**

- Find the receipt minting function; verify it is gated by the `LiquidStakingPoolCap` or equivalent privileged capability and is not callable by users directly
- Check all receipt split and merge operations: `split(receipt, amount)` should assert the total value of resulting receipts equals the input receipt value
- Verify the total issued receipt value is tracked and capped: `assert!(pool.total_issued + mint_amount <= pool.total_stake, ERROR_OVERCOLLATERALIZED)`
- Check whether receipts have `store` ability allowing them to be placed in unexpected locations that bypass the normal redemption path

**False Positives**

- Receipt minting is gated by a capability object held only by the staking contract's admin or the staking contract itself
- Total issued receipt value tracked and enforced; no path allows issuing more receipt value than underlying stake

---

### Validator Commission Manipulation in Wrapped Staking

**Protocol-Specific Preconditions**

- Protocol stakes SUI with validators on behalf of users; the validator selection logic uses a commission rate stored in a mutable config
- A validator can increase their commission rate after the protocol has delegated to them, reducing the yield returned to stakers without the protocol automatically switching validators
- No maximum commission rate enforced at delegation time; the protocol does not re-validate commission rates on each epoch boundary

**Detection Heuristics**

- Check whether the protocol validates the validator's commission rate before delegating and on each epoch when claiming rewards
- Verify whether there is a maximum acceptable commission rate: `assert!(validator.commission_rate <= MAX_COMMISSION_BPS, ERROR_HIGH_COMMISSION)`
- Check whether the protocol automatically redelegates from validators that exceed the maximum commission rate
- Verify the validator selection algorithm is not manipulable by an attacker who controls a high-commission validator with favorable other parameters

**False Positives**

- Protocol enforces a maximum commission rate at delegation and re-checks it at every reward claim epoch
- Validator selection is governance-controlled with a whitelist that requires explicit governance approval to update
