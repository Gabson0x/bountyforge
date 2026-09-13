# FV-ANC-3-CL7 Duplicate Mutable Accounts

## TLDR

When two mutable account fields in an Anchor context can be satisfied by the same public key, an attacker can pass the same account for both. Instructions that assume the accounts are distinct (e.g., transferring between them) will produce incorrect results or allow double-mutation exploits.

## Detection Heuristics

**Two mut Accounts of the Same Type Without Uniqueness Constraint**
- Context struct has `pub user_a: Account<'info, User>` and `pub user_b: Account<'info, User>`, both with `#[account(mut)]`, and no `constraint = user_a.key() != user_b.key()`
- Source and destination token accounts, or two vaults, declared as mutable without a key-inequality constraint

**Transfer Logic Assuming Distinct Accounts**
- Instruction performs `from.amount -= value` and `to.amount += value` where `from` and `to` could be the same account, resulting in net zero effect or data corruption
- Self-transfer path not considered in tests or constraints

**Accounts With Overlapping Seeds**
- Two PDA accounts derived with different logical roles but whose seeds can be made equal by an attacker choosing inputs

## False Positives

- Instruction explicitly handles the case where both accounts are the same (e.g., a no-op self-transfer path with a guard)
- Accounts are derived from distinct constant seeds that cannot collide
