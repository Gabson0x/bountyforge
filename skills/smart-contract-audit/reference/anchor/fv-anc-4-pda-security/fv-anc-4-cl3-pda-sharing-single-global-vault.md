# FV-ANC-4-CL3 PDA Sharing / Single Global Vault

## TLDR

A vault PDA derived from constant seeds (e.g., only `b"vault"`) is shared across all users or positions. Compromising any single user's position, or exploiting any instruction that touches the vault, can drain funds belonging to all other users.

## Detection Heuristics

**Vault PDA Without Per-User Seed Component**
- `Pubkey::find_program_address(&[b"vault"], program_id)` or `#[account(seeds = [b"vault"], bump)]` used for a vault that holds funds on behalf of multiple distinct users
- Global singleton PDA used as an escrow or collateral pool that does not segregate balances by user key

**Single Authority Over Multi-User Pool**
- One PDA signs for all withdrawals from a pool that aggregates multiple users' deposits without per-user sub-accounts

**Seed Does Not Include User-Identifying Component**
- PDA seeds for token vaults, collateral accounts, or staking positions do not include `user.key().as_ref()`, `position_id`, or another per-entity discriminator

## False Positives

- Single global vault is intentional (e.g., a liquidity pool or AMM reserve) and the protocol tracks per-user balances in separate accounting accounts rather than via vault segregation
- Global vault is protected by a multisig or governance authority and individual user positions are represented by separate non-vault PDAs
