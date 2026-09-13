# Lending and Vault Security Patterns (Sui/Move)

> Applies to: Scallop, Navi Protocol, Suilend, Bucket Protocol, any Move module implementing collateralized lending, overcollateralized borrowing, CDP (collateralized debt position), flash loan providers, yield vaults, share-based deposit pools on Sui

## Protocol Context

Lending protocols on Sui use Move's capability pattern extensively: a `LendingPoolCap` or similar object gates privileged operations. Liquidation is synchronous (within a single PTB), unlike async models, which means collateral seizure and debt repayment are atomic. The key risks are oracle-dependent health factor accuracy, share-based vault inflation, and liquidation incentive gaps for dust positions. Flash loans on Sui follow the hot-potato pattern and are structurally sound if the receipt is correctly non-droppable; the main risk is the repayment validation logic.

## Bug Classes

---

### Vault Share Inflation via Donation

**Protocol-Specific Preconditions**

- Vault's `total_assets()` reads the live balance of its treasury or reserve coin rather than a tracked internal counter
- First depositor can manipulate the share price by donating coins directly to the vault's treasury object, increasing `total_assets` without increasing `total_supply`
- Subsequent depositor's share calculation: `shares = deposit * total_supply / total_assets` rounds to 0, causing the deposit to be absorbed by the attacker

**Detection Heuristics**

- Find the vault's `total_assets` computation; check whether it calls `balance::value(&vault.reserves)` on a live object or reads a tracked `deposited_amount` field
- Check the first deposit case: if `total_supply == 0`, verify a minimum number of dead shares are minted to a zero address or a virtual offset is applied
- Verify that the `deposit` function uses `(deposit + VIRTUAL) * (total_supply + VIRTUAL) / (total_assets + VIRTUAL)` or an equivalent inflation-resistant formula
- Test: deposit 1 MIST, donate 1e9 MIST to the vault reserves object directly, attempt a 1e9 MIST deposit; verify the second depositor receives non-zero shares

**False Positives**

- Vault tracks deposited assets in a dedicated `u64` field updated only through the deposit function; coin donations to the reserves object do not affect `total_assets()`
- Virtual shares offset applied at initialization makes the inflation attack require a donation larger than any realistic attack budget

---

### Oracle-Dependent Health Factor Errors

**Protocol-Specific Preconditions**

- Health factor computation reads oracle price without staleness or confidence check; stale prices from a halted oracle feed keep a position appearing healthy when it is actually undercollateralized
- Health factor computed before accruing interest, causing understated debt and preventing correct liquidation
- Decimal normalization error in oracle price consumption: oracle returns price in a different decimal scale than the protocol's internal accounting, causing systematic mis-pricing of collateral

**Detection Heuristics**

- Trace the health factor calculation from collateral value through oracle price to the comparison against liquidation threshold; verify staleness and confidence are checked at the oracle read
- Verify that `accrue_interest()` is called as the first step in any health factor computation, before oracle reads or balance checks
- Check all oracle price normalizations: `price * (10 ^ (protocol_decimals - oracle_decimals))`; verify this computation is correct for every supported asset including those with non-18 decimals
- Verify that the liquidation threshold comparison is: `collateral_value * ltv_ratio > debt_value * 10000`, not an inverted or incorrect inequality

**False Positives**

- Health factor computation uses `get_price_no_older_than` with an appropriate max age and confidence check before every use
- Interest accrual is always the first operation in health factor computation, enforced by a wrapper function called at every entry point

---

### Liquidation Dust Position Griefing

**Protocol-Specific Preconditions**

- Liquidation bonus is a percentage of the collateral value; for small positions, the bonus is less than the on-chain transaction fee, leaving the position permanently unliquidatable
- No minimum position size enforced; positions can be opened at any collateral value
- Partial repayment can reduce a position to below the minimum viable size, creating a permanent dust residue

**Detection Heuristics**

- Calculate the minimum collateral value at which the liquidation bonus exceeds the maximum expected Sui transaction gas fee
- Check whether `open_position` and `repay` enforce a minimum position size: `assert!(collateral_value >= MIN_COLLATERAL_USD, ERROR_TOO_SMALL)`
- Verify that after a partial liquidation, the remaining position either meets the minimum size or is fully liquidated; no partial liquidation should leave a dust residue
- Check for a protocol-sponsored cleanup function that can forcibly close dust positions at no liquidation bonus

**False Positives**

- Minimum position size enforced at creation, repayment, and liquidation; all three entry points have the same minimum check
- Protocol charges a dust fee at position creation that makes opening small positions economically unattractive

---

### Self-Liquidation for Bonus Extraction

**Protocol-Specific Preconditions**

- Liquidator and borrower can be the same address; no check in the liquidation entry function
- Liquidation bonus paid to the liquidator on top of the debt repaid; if self-liquidation is allowed, the borrower can pay their own debt and receive back their collateral plus the bonus
- Liquidation fee charged to the borrower does not fully offset the bonus paid to the liquidator when they are the same party

**Detection Heuristics**

- Find the liquidation entry function; check for `assert!(liquidator_address != borrower_address, ERROR_SELF_LIQUIDATION)`
- Calculate the net profitability of self-liquidation: `bonus_received - liquidation_fee_paid`; if positive, self-liquidation is profitable
- Check whether the protocol explicitly documents self-liquidation as an intended feature; if not, it is an oversight

**False Positives**

- Protocol explicitly prohibits self-liquidation via an assert on liquidator != borrower
- Liquidation fee is equal to or greater than the bonus, making self-liquidation economically neutral or negative
