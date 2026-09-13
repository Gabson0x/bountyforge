# Lending and Vault Security Patterns (TON)

> Applies to: TON lending protocols, collateralized borrowing contracts, vault share protocols, Jetton-based money markets, stablecoin CDPs, over-collateralized loan contracts, flash loan providers, any FunC or Tact contract that issues shares against deposited Jetton or TON collateral

## Protocol Context

Lending and vault protocols on TON face the same fundamental share-accounting and liquidation vulnerabilities as EVM counterparts but with important TON-specific complications. The async message model means liquidation is not atomic: a liquidator sends a message, the lending contract processes it, and the collateral release is a separate outbound message. Between these hops, the collateral value can change and the liquidation can become unprofitable or under-collateralized. Vault share inflation via direct Jetton transfers is trivially executable on TON because any address can send Jetton transfer notifications to any contract; the contract must not derive its total_assets from the raw Jetton balance.

## Bug Classes

---

### Vault Share Inflation

**Protocol-Specific Preconditions**

- Vault computes `total_assets` from its Jetton balance (read from the Jetton wallet via `op::get_wallet_data` or inferred from received transfer notifications) rather than from a tracked internal counter
- First depositor inflates the share price by sending a direct Jetton transfer to the vault's wallet address (not through the deposit op-code), which increases the vault's Jetton balance without updating `total_supply`
- Next depositor's share calculation: `shares = deposit * total_supply / total_assets` yields 0 due to the inflated denominator, and the deposit is absorbed by the attacker as excess assets per share

**Detection Heuristics**

- Find the `total_assets` (or equivalent) computation in the vault contract; check whether it reads a tracked internal variable or uses the raw Jetton balance
- Check the first deposit case: if `total_supply == 0`, what happens? Verify a minimum shares amount is minted to a dead address at initialization to anchor the share price
- Verify whether the virtual shares pattern is applied: `shares = (deposit + VIRTUAL) * (total_supply + VIRTUAL) / (total_assets + VIRTUAL)`; if not, first-depositor inflation is possible
- Test: deploy vault, deposit 1 unit (get 1 share), donate 1e9 units directly to Jetton wallet, attempt 1e9 deposit; verify the second depositor receives > 0 shares

**False Positives**

- Vault tracks deposited assets in a persistent variable updated only through the deposit op-code handler; direct Jetton transfers are ignored or rejected
- Virtual shares pattern applied with an offset large enough to make the inflation attack economically unattractive

---

### Liquidation Not Atomic in Async Model

**Protocol-Specific Preconditions**

- Liquidation involves two or more message hops: (1) liquidator sends `op::liquidate` to lending contract, (2) lending contract sends `op::transfer` of collateral to liquidator
- Between message (1) and message (2) processing, the collateral's oracle price can change
- No reserve for worst-case liquidation bonus is locked at message (1) receipt; the bonus is computed from the oracle price available at message (2) processing time

**Detection Heuristics**

- Trace the liquidation message sequence; check whether the collateral amount is determined at the first message or at a later hop
- Verify that the protocol checks the borrower's collateral availability at message receipt time and locks the exact collateral amount before sending the outbound release message
- Check whether the liquidation bonus is computed from a price snapshot taken at `op::liquidate` receipt or from the current oracle price at collateral release time
- Verify that if the collateral value drops between the liquidation request and the release, the liquidation does not result in the protocol being undercollateralized

**False Positives**

- Collateral is locked (marked as in-use) at `op::liquidate` receipt and the locked amount is sent regardless of subsequent price changes
- Protocol uses a conservative price haircut at liquidation request time that is sufficient to cover price volatility during the message processing window

---

### Insufficient Liquidation Incentive for Dust Positions

**Protocol-Specific Preconditions**

- Liquidation bonus is a percentage of the collateral value; small positions yield a bonus smaller than the TON gas cost to execute the liquidation
- No minimum position size enforced; positions can be opened at any size
- Dust positions accumulate as bad debt because no external liquidator is economically motivated to close them

**Detection Heuristics**

- Calculate the minimum collateral value at which the liquidation bonus exceeds the expected TON gas cost for the full liquidation message chain
- Check whether the lending contract enforces a `min_collateral_value` at position open time and at partial repayment time
- Verify the protocol has a mechanism to close dust positions, such as a privileged admin function or a protocol-sponsored dust sweeper
- Count the number of messages in the liquidation flow; each additional hop increases the gas cost and the minimum economically viable position size

**False Positives**

- Minimum position size is enforced such that the liquidation bonus at the minimum position size always exceeds the maximum expected gas cost for the liquidation flow
- Protocol has a documented dust handling mechanism and the minimum position size is reviewed against current TON gas prices

---

### Bad Debt Not Socialized

**Protocol-Specific Preconditions**

- When a liquidation leaves the protocol with more debt than collateral (bad debt), no insurance fund or socialization mechanism absorbs the residual
- Bad debt is silently accumulated in the protocol's accounting, creating a growing deficit between tracked liabilities and actual assets
- Eventual withdrawal run: when total withdrawals exceed total deposits minus accumulated bad debt, the protocol becomes unable to honor remaining withdrawals

**Detection Heuristics**

- Check the liquidation handler for a case where `debt_value > collateral_value`; what happens to the residual debt?
- Look for an insurance fund or bad debt tracker variable; verify it is funded and checked when bad debt occurs
- Verify that `total_liabilities` (what the protocol owes depositors) and `total_assets` (what the protocol holds) stay in sync after every operation including partial liquidations
- Check whether the protocol ever writes off bad debt by reducing depositor claims proportionally (socialization) or absorbing it from a reserve

**False Positives**

- Insurance fund covers bad debt up to a documented maximum; protocol documentation acknowledges and accepts the residual risk above this threshold
- Socialization mechanism explicitly reduces depositor shares proportionally when bad debt exceeds the insurance fund, with governance approval required
