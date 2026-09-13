# FV-ANC-11-CL6 Reward Accumulator Updated After Balance Change

## TLDR

Staking and reward protocols that track per-share reward accumulation must update the global accumulator index before modifying any user's share balance. If the index is updated after a deposit or withdrawal, the user's new balance is used to calculate their retroactive entitlement to rewards that accrued before the balance change, allowing them to claim rewards they did not earn.

## Detection Heuristics

**Index Updated After Balance Mutation**
- `global_reward_index` updated after `user.shares += deposit_amount` or `user.shares -= withdraw_amount` in the same instruction
- Instruction flow: read old balance -> add deposit -> update index -> calculate pending rewards using new balance; the update should occur before the balance change
- `pending_rewards = (global_index - user.last_index) * user.shares` computed with a shares value that already includes the new deposit

**Snapshot Not Taken Before Balance Change**
- No `old_shares` snapshot taken before the balance modification; reward calculation uses `user.shares` which may already be the post-deposit value
- `accumulate_rewards(user)` function reads `user.shares` from the account state; if called after the balance is updated, it captures the wrong shares for historical reward calculation

**Instant Deposit-and-Claim**
- Attacker can deposit, immediately claim rewards that accrued before their deposit, and withdraw in the same slot because the index is stale at deposit time
- No minimum time between deposit and first reward claim; instant claim on a freshly accrued index is the exploit vector

## False Positives

- Protocol always calls `settle_rewards(user)` as the first step of any instruction that modifies balances; this settles outstanding rewards at the old balance before any mutation occurs
- Reward index updated atomically at the global level before any per-user mutation; all pending rewards calculated and credited using the pre-mutation share count
