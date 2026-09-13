# FV-ANC-7-CL5 Interest-Bearing Mint Principal vs Balance Confusion

## TLDR

Token-2022 interest-bearing mints compound an on-chain rate that increases the displayed token balance over time. Programs that read the raw `TokenAccount.amount` without calling the extension's `amount_to_ui_amount` conversion will undercount the actual accrued value, leading to mispriced collateral, incorrect liquidation thresholds, or silent yield extraction by users who understand the accounting gap.

## Detection Heuristics

**Raw Amount Read Without Interest Normalization**
- Protocol reads `token_account.amount` on a Token-2022 interest-bearing mint and uses it directly in a collateral value or share price calculation
- No call to `spl_token_2022::extension::interest_bearing_mint::amount_to_ui_amount` or equivalent before arithmetic on the token amount
- Comparison of token amounts across different timestamps without normalizing both values to the same accrued-interest basis

**Mint Extension Not Checked at Initialization**
- Vault or pool initialization does not inspect the mint account for the `InterestBearingConfig` extension before accepting the mint
- Protocol documentation claims to handle interest-bearing tokens but accounting code uses raw `amount` without adjusting for the configured rate and elapsed time

**Reward or Collateral Valuation Bypass**
- Attacker deposits tokens, waits for interest to accrue, then withdraws at the original amount rather than the inflated displayed amount, pocketing the difference
- Protocol applies interest only at the contract level but ignores Token-2022 on-chain interest extension, double-counting or missing yield

## False Positives

- Protocol explicitly rejects interest-bearing mints at initialization by checking for the absence of `InterestBearingConfig` extension and reverting if found
- Interest-bearing rate on the mint extension is set to 0, making accrued interest zero across all time
