# FV-ANC-10-CL3 Unintended Closure by close Constraint

## TLDR

Anchor's `close` constraint closes the account and transfers its lamports at the end of the instruction, regardless of what the instruction body does. Applying it to accounts that should only conditionally be closed, or misunderstanding when the closure executes, can lead to unintended data and lamport loss.

## Detection Heuristics

**Unconditional close on Conditionally-Closed Accounts**
- `#[account(mut, close = destination)]` applied to an account that should only be closed under certain runtime conditions
- Instruction body contains early-return paths that the developer assumes will prevent closure, but closure still occurs because Anchor's drop handler runs regardless

**close Applied to Accounts Used Later in the Same Instruction**
- Account fields read or written after the instruction body but whose lamports will be zeroed by the close handler, causing incorrect post-instruction state assumptions
- CPI made after the instruction body that passes the to-be-closed account as a writable signer

**Incorrect Destination for Lamport Transfer**
- `close = destination` points to a user-supplied account not validated by a `has_one` or `address` constraint, allowing lamports to be redirected

## False Positives

- `close` is the correct and intended behavior for the instruction and the account lifecycle is well-defined
- `close` combined with a `constraint` that enforces the conditions under which closure is valid, making it effectively conditional
