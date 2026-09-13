# FV-SOL-9-C8 Dust and Threshold Griefing

## TLDR

Two griefing patterns exploiting minimal-cost interactions: a dust deposit with no minimum amount can reset a per-user timelock indefinitely, and a dust token transfer to a contract can permanently block a zero-balance gate that guards a state transition.

## Detection Heuristics

**Dust Deposit / Timelock Reset**
- `lastActionTime[user] = block.timestamp` inside a deposit or action function with no `require(amount >= MIN)` guard
- Timelock or cooldown resets on any deposit regardless of amount
- No per-user isolation: an attacker targeting another user's lock by calling the function on their behalf

**Zero Balance Check Griefing**
- `require(token.balanceOf(address(this)) == 0)` gates a state transition
- Direct token transfers to the contract are not rejected (no `receive()` guard, token is ERC20 pushable)
- State transition is access-restricted but the balance check remains exploitable via a direct token send

## False Positives

- Minimum deposit enforced unconditionally (`require(amount >= MIN_DEPOSIT)`)
- Cooldown assessed only at withdrawal time using deposit amount, not reset on small deposits
- Threshold check (`<= DUST_THRESHOLD`) instead of exact `== 0`
- Function is access-controlled such that only trusted addresses can call it
