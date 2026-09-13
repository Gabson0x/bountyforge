# FV-ANC-3-CL5 No is_initialized Check When Operating on an Account

## TLDR

Operating on an uninitialized account allows instructions to read garbage data or overwrite state during initialization with attacker-controlled values. Anchor's `#[account(init)]` guards against double-initialization, but manually managed accounts or legacy patterns that track initialization via a boolean flag must be explicitly checked.

## Detection Heuristics

**Missing Initialization Guard on Manual Account Structs**
- Account struct contains `is_initialized: bool` field but no instruction reads this field and rejects the account if already initialized
- Instruction that should only run once does not check `is_initialized` before writing state

**init_if_needed Without Subsequent State Validation**
- `#[account(init_if_needed)]` used without checking whether the account was already initialized before writing fields, allowing re-initialization with new values

**Operating on Zero-Discriminator Account**
- Instruction accepts an `Account<'info, T>` that should be freshly initialized but does not use `init` constraint, allowing an all-zero account to pass deserialization

## False Positives

- Anchor `#[account(init)]` constraint is used, which enforces that the account is uninitialized (all-zero discriminator) at the time of the instruction
- Instruction is explicitly designed to re-initialize an account and documents this behavior
