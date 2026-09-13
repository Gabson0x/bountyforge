# FV-ANC-1-CL5 Round-Trip Vault Profit via Precision Gap

## TLDR

A deposit followed by an immediate withdrawal can extract value when share-to-asset conversion rounds in the depositor's favor at both steps. When both mint and redeem paths round down at the asset level, an attacker can systematically drain dust from a vault across many round-trip transactions, particularly in low-liquidity pools or at initialization.

## Detection Heuristics

**Symmetric Rounding Favoring Depositor**
- Vault deposit computes shares as `assets / price_per_share` (truncating division) and withdrawal computes assets as `shares * price_per_share` (also truncating) without a rounding direction that favors the vault
- Neither deposit nor withdrawal applies a minimum delta fee to make round-trips economically unviable
- Test with small deposit amounts (1-10 units) to check if `assets_out >= assets_in` after an immediate withdrawal

**Share Price Manipulation via Empty Vault**
- Vault can be initialized with 0 total_supply; first depositor can manipulate the initial share price by donating tokens directly to the vault account before anyone else deposits
- `total_assets()` reads the token account balance directly rather than a stored tracked value, making it susceptible to donation inflation
- Initialization does not mint a minimum set of shares to a dead address to anchor the initial share price

**Missing Deposit or Withdrawal Fee**
- No `deposit_fee_bps` or `withdrawal_fee_bps` applied in the deposit or withdrawal paths
- Fee, if present, is set to 0 by default and not enforced at protocol level for all vault types

## False Positives

- Vault enforces a minimum deposit amount greater than the maximum rounding delta per operation
- Deposit and withdrawal fees make the round-trip economically negative for the attacker at all meaningful scales
- Vault uses the ERC-4626-equivalent virtual offset (adding 1 to total_assets and total_supply at deployment) to anchor the initial share price and prevent inflation attacks
