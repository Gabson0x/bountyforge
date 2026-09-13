# Lending and Vault Security Patterns

> Applies to: lending protocols, borrowing protocols, collateralized debt positions, money markets, flash loan providers, yield vaults, ERC-4626-equivalent share vaults, isolated lending markets, overcollateralized lending, undercollateralized lending on Solana

## Protocol Context

Lending protocols on Solana maintain supply shares representing depositor claims and debt shares representing borrower obligations, where a compounding borrow index continuously shifts the exchange rate between shares and underlying token amounts. Liquidation correctness depends entirely on oracle price accuracy and freshness at the moment of the health factor check. Share-based vault accounting introduces a distinct class of inflation and rounding vulnerabilities specific to the deposit-to-share conversion math, particularly at vault initialization when total supply is zero or near-zero.

## Bug Classes

---

### Vault Share Inflation (ref: fv-anc-1-cl5)

**Protocol-Specific Preconditions**

- Vault can be initialized with zero total supply; first depositor controls the initial share price via direct token donation to the vault token account
- `total_assets()` reads the live token account balance directly rather than a tracked internal variable, making it manipulable by donation
- No virtual shares or minimum initial deposit to anchor the share price at initialization

**Detection Heuristics**

- Find the vault's `total_assets` or `total_supply` computation; check whether it reads a live token balance or a stored tracked value
- Identify whether a first depositor with a very small deposit amount followed by a donation can make the share price so high that subsequent depositors receive 0 shares due to rounding
- Check whether `deposit` and `withdraw` rounding directions consistently favor the vault (shares minted round down, assets owed on withdraw round up)
- Test deposit of 1 lamport followed by direct token transfer to the vault; verify subsequent depositors still receive non-zero shares

**False Positives**

- Protocol mints a minimum set of dead shares at initialization to anchor the price and prevent first-depositor manipulation
- `total_assets()` reads a stored tracked field that is updated only through protocol instructions, not the live token balance

---

### Liquidation Logic Flaws (ref: fv-anc-4-cl4)

**Protocol-Specific Preconditions**

- Health factor computation reads oracle price without freshness or confidence check; undercollateralized positions may not be flagged during oracle outages
- Liquidation instruction shares a pause flag with deposit or repay operations; pausing any operation also blocks liquidations
- Liquidation profit (bonus) not large enough to cover transaction costs and slippage, creating conditions where no liquidator executes and bad debt accumulates
- Minimum liquidation amount too large to close dust positions; dust positions accumulate as uncollectable bad debt

**Detection Heuristics**

- Trace the health factor calculation from account data through oracle price to the comparison threshold; verify oracle freshness is checked at this exact point
- Check whether liquidation is gated by any `require!(!paused)` that also blocks deposits or other user operations
- Verify the liquidation incentive (bonus_bps) is sufficient to cover on-chain fees and typical slippage for the collateral types supported
- Check the minimum liquidation threshold; verify dust positions at or below this threshold do not permanently evade liquidation

**False Positives**

- Health factor computation always calls oracle with staleness check as its first step, before any arithmetic
- Pause mechanism has separate flags for user operations and protocol liquidations; liquidations are never blocked by user-operation pauses

---

### Self-Liquidation for Profit (ref: fv-anc-2-cl1)

**Protocol-Specific Preconditions**

- Liquidator and borrower are permitted to be the same address; no restriction preventing a position holder from liquidating their own position
- Liquidation bonus paid on top of debt repayment makes self-liquidation profitable if the protocol allows it
- No check that `liquidator.key != borrower.key` in the liquidation instruction

**Detection Heuristics**

- Check the liquidation instruction accounts constraints for a `constraint = liquidator.key() != borrower.key()` assertion
- Calculate the effective profit of a self-liquidation: if the liquidation bonus exceeds the liquidation fee and any protocol penalty, self-liquidation is profitable
- Verify whether self-liquidation is documented as an intentional feature or an oversight

**False Positives**

- Protocol explicitly allows self-liquidation as a mechanism for borrowers to exit positions and documents this as intentional
- Liquidation fee or protocol penalty makes self-liquidation economically neutral or negative for the liquidator

---

### Interest Accrual During Pause

**Protocol-Specific Preconditions**

- Protocol can be paused to prevent deposits, withdrawals, and liquidations
- Borrow index continues to compound during the pause period, increasing borrower debt without borrowers being able to repay or liquidators being able to act
- After a long pause, borrowers whose positions were healthy at pause time are liquidatable on resume because debt grew beyond collateral value

**Detection Heuristics**

- Identify the pause mechanism; check whether interest accrual is also paused or continues independently
- Calculate the maximum pause duration that would make a healthy position at the boundary of the liquidation threshold become undercollateralized
- Verify whether governance documentation or code enforces a maximum pause duration that prevents this scenario

**False Positives**

- Interest accrual is explicitly stopped by the pause mechanism; the borrow index is not updated during paused state
- Pause duration is hard-capped in the program to a duration short enough that even highly leveraged positions cannot become undercollateralized from interest alone

---

### Precision Loss in Borrow Index Scaling

**Protocol-Specific Preconditions**

- Borrow index stored as a u64 or u128 scaled value; interest rate application involves division that truncates
- Small borrows accumulate less interest than expected due to repeated truncation of fractional interest amounts
- Fee calculations using basis points truncate to zero for small positions, allowing fee-free operation below a certain size threshold

**Detection Heuristics**

- Find the borrow index update function; check the scaling factor (1e9, 1e18) and whether intermediate multiplications use u128 to prevent overflow
- Test with minimum borrow amounts to verify that interest accrues correctly and does not round to zero indefinitely
- Verify that fee computations use `checked_mul` before `checked_div` to minimize precision loss

**False Positives**

- Protocol uses u128 throughout interest calculations with a scaling factor of 1e18; rounding loss bounded to 1 unit per operation
- Minimum borrow amount enforced to be large enough that interest accrual is always non-zero
