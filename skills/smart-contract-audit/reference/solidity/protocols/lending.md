# Lending and Borrowing Security Patterns

> Applies to: lending protocols, borrowing protocols, CDP (collateralized debt position), collateral-backed loans, uncollateralized lending, flash loans, money markets, Aave-style, Compound-style, MakerDAO-style

## Protocol Context

Lending protocols maintain a dual-ledger of supply shares (representing depositor claims on pooled assets) and debt shares (representing borrower obligations scaled by a compounding borrow index), where interest accrual continuously shifts the exchange rate between shares and underlying assets. Liquidation mechanics depend on oracle-reported collateral values being accurate and timely enough that undercollateralized positions can be closed before bad debt accumulates, making oracle reliability and liquidation incentive math critical invariants. Share-based deposit accounting introduces a class of inflation and rounding vulnerabilities unique to these protocols, where the relationship between total assets and total shares can be manipulated by the first depositor or by direct token donations to the pool.

## Bug Classes

### Reentrancy (ref: fv-sol-1)

**Protocol-Specific Preconditions**

- Token transfers in deposit, withdraw, repay, or liquidate fire ERC-777 `tokensReceived` or ERC-721 `onERC721Received` callbacks before position state is updated
- Protocols integrated with Balancer or Curve expose view functions (LP price, `virtual_price`) that are read by external liquidators during a callback window where pool balances and token supply are transiently desynchronized (read-only reentrancy)
- ETH-handling vaults send native ETH via `call` before burning shares or updating debt
- OpenZeppelin `initializer` modifier versions prior to 4.3.2 are reentrancy-unsafe during proxy initialization

**Detection Heuristics**

- Find every external call (token transfer, ETH `call`, swap router interaction) and check whether any accounting variable - share balance, borrow balance, liquidity index - is read before the call and written after it
- Check that all state-mutating functions share a reentrancy lock; a guard on `deposit` alone does not protect `borrow` if an attacker can reenter through a callback
- For Balancer and Curve LP collateral oracles, check whether the consuming contract calls `VaultReentrancyLib.ensureNotInVaultContext` or the Curve equivalent before reading `virtual_price` or BPT supply
- Search for `receive()` and `fallback()` functions in contracts that hold ETH positions; any ETH send before share accounting is a reentrancy surface

**False Positives**

- Protocols that exclusively handle standard ERC-20 tokens with no callback hooks and no ETH
- Functions where the Checks-Effects-Interactions pattern is strictly followed with a `nonReentrant` guard
- Read-only reentrancy when the consuming contract verifies the source vault's reentrancy lock state before reading

**Notable Historical Findings**

Balancer-integrated lending protocols have been exploited via read-only reentrancy: an attacker enters a Balancer join callback at the moment BPT supply is updated but token balances are not, causing LP price oracles consumed by the lending protocol to return an inflated value that prevents correct liquidation. Protocols built on JPEG'd experienced a classic deposit reentrancy where the share minting step occurred after the token pull, allowing ERC-777 tokens to re-enter `deposit` with the same stale `balanceBefore`, minting unbounded extra shares. ZeroLend's NFTPositionManager had multiple reentrancy-adjacent issues where repay and reward claim paths shared mutable state without consistent locking.

**Remediation Notes**

Apply `nonReentrant` to every external-facing function that modifies supply or borrow accounting, not just the primary deposit path. For LP token price consumers, integrate the source protocol's reentrancy guard check as the first statement. For ETH vaults, burn shares and update balances before executing the ETH send.

---

### Precision and Rounding Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**

- Share-to-asset and asset-to-share conversions involve division by a dynamic index (liquidityIndex, borrowIndex) that grows over time; truncation at each operation compounds across the life of a pool
- Collateral value calculations combine token amounts from pools with different decimals (USDC at 6, WETH at 18) against oracle feeds that may return 8 or 18 decimal prices
- Rounding direction in ERC-4626-style vaults must favor the protocol: shares minted on deposit should round down, assets owed on withdraw should round up - inverting this direction allows users to extract value over many operations
- Interest accrual formulas that use linear approximations instead of compound formulas accumulate material divergence from expected values at high utilization over long periods

**Detection Heuristics**

- Find all expressions of the form `(a / b) * c`; the division truncates before the multiplication, losing precision. Rewrite as `(a * c) / b` or use `mulDiv`
- Check every oracle consumption site for a hardcoded decimal assumption (`price / 1e8`, `price / 1e18`); verify it matches the actual feed decimals for every supported asset, including assets added after deployment
- In share conversion functions, confirm the rounding direction parameter (`Math.Rounding.Down` vs `Math.Rounding.Up`) is consistent with what the protocol's security invariant requires
- For fee calculations using basis points, verify that small pool sizes do not cause fee amounts to round to zero across many calls, allowing fees to be permanently avoided

**False Positives**

- Precision loss bounded to 1 wei per operation with no cumulative economic path
- Protocols that explicitly document a supported decimal range for tokens and reject others via a whitelist
- `mulDiv` with rounding-up variants applied correctly to critical conversions

**Notable Historical Findings**

Notional Leveraged Vaults had a wrong decimal precision issue where inflated prices resulted from mismatched decimal normalization between the oracle feed and the underlying token. JPEG'd suffered a `pricePerShare` calculation that truncated to zero for non-18-decimal tokens, breaking share valuation for any pool using USDC-denominated assets. ZeroLend's `GenericLogic` assumed all Chainlink feeds return the same number of decimals, causing incorrect health factor calculations when different asset feeds used 8 versus 18 decimal representations. Numoen had a division-before-multiplication precision loss in its invariant function that allowed attacks to drain funds on low-decimal token pairs.

**Remediation Notes**

Normalize all oracle prices to a common internal precision (typically 1e18) at the point of consumption, storing the feed's decimal count separately from its raw value. For share math, adopt the ERC-4626 virtual offset pattern or explicitly use `mulDiv` with correct rounding direction at every conversion boundary.

---

### Access Control and Authorization Failures (ref: fv-sol-4)

**Protocol-Specific Preconditions**

- `onBehalf` parameters in repay, liquidate, or redeem functions are checked only for non-zero address, not for ownership of the position being acted upon
- NFT collateral auctions allow any caller to claim proceeds or the NFT itself after time expiry without verifying they are the winning bidder
- L2 deployments consuming Chainlink feeds do not check sequencer uptime before accepting price data; a sequencer outage causes oracle staleness that can be exploited in the grace period after restart
- Position mode changes (e.g., isolated mode, e-mode) do not verify that the new mode is compatible with the account's current debt and collateral state

**Detection Heuristics**

- For every function accepting `onBehalf` or `for` parameters, trace whether `msg.sender`'s relationship to the named position is validated beyond null checks
- Audit functions in liquidation paths (auction claim, collateral seizure, NFT unlock) for caller authorization
- On Arbitrum and Optimism deployments, check for `sequencerUptimeFeed.latestRoundData()` calls with a grace period enforcement before any Chainlink price is accepted
- Review `setPosMode` and similar parameter change functions to verify health checks are re-run after the mode transition

**False Positives**

- Permissionless repayment of another user's debt when the protocol design explicitly allows it as a feature
- Access control enforced upstream in a router contract that always mediates protocol entry
- L2 sequencer checks implemented at the oracle contract level rather than individually at each consumer

**Notable Historical Findings**

BendDAO had two high-severity access control failures: `isolateRepay` accepted any `onBehalf` address without verifying NFT ownership, allowing an attacker to corrupt another user's borrow accounting and trigger underflows on subsequent liquidation; separately, the `claimAuctionNFT` function transferred the NFT to any caller after auction expiry without checking that the caller was the highest bidder. ZeroLend's NFTPositionManager enforced address symmetry that broke Account Abstraction wallets where the signing address differs from the execution address. Blueberry Update's oracle layer did not check whether the Arbitrum sequencer was active, exposing the protocol to stale price attacks during sequencer downtime windows.

**Remediation Notes**

For `onBehalf` parameters, require that the caller is either the position owner or holds an explicit delegation grant stored on-chain. For L2 oracle consumers, implement the sequencer uptime pattern as a shared library or base contract to ensure consistent enforcement across all markets.

---

### Slippage Protection (ref: fv-sol-8)

**Protocol-Specific Preconditions**

- Position open, close, and liquidation flows perform DEX swaps (Uniswap, Curve, Balancer) where the minimum output is hardcoded, set to zero, or calculated from a potentially stale oracle price
- Reward token harvests swap externally claimed rewards (CRV, AURA, CVX) without user-configurable slippage, making these transactions predictable MEV targets
- Protocols using UniswapV3 may rely on `sqrtPriceLimitX96` for price control, which causes partial fills rather than reverts when the limit is reached - leaving residual tokens in the contract
- `block.timestamp` passed as a deadline provides no protection; validators or searchers can hold transactions and execute them at a later, disadvantageous block

**Detection Heuristics**

- Search for router calls (`swapExactTokensForTokens`, `exactInputSingle`, `swap`) where `amountOutMin` or its equivalent is a literal `0` or a constant
- Identify UniswapV3 `swap()` calls relying solely on `sqrtPriceLimitX96`; confirm there is a post-swap check that the full intended amount was swapped
- Verify that deadline parameters passed by users are forwarded to the swap call, not replaced with `block.timestamp`
- Check reward harvest functions for per-reward-token slippage parameters; broad "harvest all" calls without individual minimums are sandwich targets

**False Positives**

- Swaps executed via private relays (Flashbots, MEV-Share) where mempool exposure is eliminated
- Protocol-controlled admin swaps with off-chain price verification and governance oversight
- Swap amounts that are trivially small relative to pool depth, making sandwich attacks unprofitable after gas

**Notable Historical Findings**

Blueberry Update had multiple slippage issues: the UniswapV3 `sqrtRatioLimit` was used as slippage protection but causes partial fills, leaving tokens stuck; reward token swaps had no minimum output at all; and a deadline check using `block.timestamp` was recognized as non-functional. Wise Lending had a hardcoded Uniswap fee tier that did not adapt to pool conditions. Notional Leveraged Vaults lacked slippage control on PT redemption and sUSDe liquidation paths, creating sandwich attack vectors. JOJO Exchange's flash loan liquidator had no slippage control when converting seized collateral to USDC.

**Remediation Notes**

Expose a `minAmountOut` and `deadline` parameter from every user-facing entry point that triggers a swap, including indirect triggers like liquidation or harvest. For reward harvests, accept a per-token minimum array. Replace any use of `sqrtPriceLimitX96` as a slippage guard with a post-swap balance check.

---

### Oracle Manipulation and Flash Loan Price Attacks (ref: fv-sol-10, fv-sol-10-c5, fv-sol-10-c6, fv-sol-10-c7)

**Protocol-Specific Preconditions**

- Collateral value is computed from AMM spot reserves or LP token prices that can be moved within a single transaction using flash-borrowed capital
- LP token pricing based on Curve `virtual_price` or Balancer BPT supply/balance is vulnerable during reentrancy windows as described in the reentrancy section
- Governance voting power or borrow limits are derived from current token balances rather than time-weighted or checkpoint-based snapshots, enabling flash loan-driven manipulation
- Reward distribution uses `rewardsPerShare += reward / totalStaked` at the time of distribution, allowing an attacker to flash-stake before the distribution call and withdraw immediately after

**Detection Heuristics**

- Identify all oracle consumption sites and classify each price source as spot, TWAP, or Chainlink; any spot AMM price is a flash loan attack surface
- Check governance and staking contracts for balance checks using `token.balanceOf(account)` at execution time rather than `getPriorVotes(account, block.number - 1)` or equivalent checkpointed values
- Look for staking deposit and withdraw in the same block without a cooldown; this enables zero-cost reward extraction around distribution events
- For CDP protocols that accept LP tokens as collateral, verify the oracle uses a TWAP of the underlying component prices rather than the raw LP reserve ratio

**False Positives**

- Price sources using Chainlink aggregators with heartbeat validation, not AMM spot prices
- Checkpoint-based voting where stakes from the current block are ineligible
- Flash loan guard patterns that check `tx.origin == msg.sender` for governance calls (acceptable in governance contexts)

**Notable Historical Findings**

Sentiment suffered a direct oracle manipulation through the ERC-4626 oracle being vulnerable to deposit-inflate-query-withdraw in the same transaction, allowing an attacker to distort collateral values and borrow against inflated positions. Blueberry's IchiLpOracle was exploited because it computed LP token value from the IchiVault's instantaneous token balance ratios, which are trivially manipulable with a flash swap. Curve LP-backed lending protocols have been attacked by manipulating `virtual_price` during remove_liquidity callbacks (read-only reentrancy), causing the collateral oracle to return a value inconsistent with the post-withdrawal state.

**Remediation Notes**

For LP token collateral, price the underlying components individually from Chainlink feeds and compute LP value from the invariant formula rather than from on-chain reserves. For governance, require checkpoint-based snapshots at a prior block for all voting weight queries.

---

### Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**

- Liquidation functions transfer the seized collateral asset directly to the liquidator; if the collateral reserve has been drained by concurrent borrows or withdrawals, the transfer reverts, blocking liquidation
- Borrowers can front-run liquidations by repaying a single debt share, changing the share count and causing the liquidator's calculated `amount <= borrowShares` check to stale-fail
- Interest accrual functions iterate over all pools or all user positions without a gas bound
- Withdrawal queues in uncollateralized lending protocols allow any depositor to add entries without limit, making queue processing and refund iteration prohibitively expensive
- Chainlink oracle heartbeat checks with a fixed threshold applied across all markets fail for assets with different update frequencies, causing healthy markets to revert on oracle calls

**Detection Heuristics**

- Check liquidation transfer paths: is the transferred asset pulled from the pool's live token balance? If yes, verify that the available balance is checked before attempting the transfer, with graceful fallback to aToken/share seizure
- Search for repay functions that check `amount <= currentBorrowShares` using a value computed before any reentrancy or front-run window; consider whether 1-share repayments can invalidate a pending liquidation
- Identify all unbounded loops and verify the iteration count is bounded by a governance-set constant, never by user-controlled array length
- For oracle staleness checks, verify each market uses the heartbeat appropriate for that specific asset feed, not a single global constant

**False Positives**

- Protocols that seize aTokens/shares rather than underlying tokens, which are immune to liquidity drain DoS
- Emergency admin functions that can manually clear stuck liquidations or override oracle failures
- Liquidation functions with partial fill semantics that cap seized collateral to available balance

**Notable Historical Findings**

ZeroLend had a liquidation DoS where the collateral reserve's available liquidity could be reduced to zero by other users borrowing the same asset before the liquidation executed, reverting the collateral transfer. Wise Lending allowed borrowers to DoS their own liquidation by repaying as little as one debt share immediately before the liquidation transaction, invalidating the liquidator's calculated parameter. BendDAO's oracle had a single heartbeat value applied to all feeds, causing a DoS on markets where the asset's native feed update frequency exceeded that threshold. Notional Leveraged Vaults exhibited a withdrawal-queue-adjacent DoS where griefing calls at high frequency on L2 caused reward accrual rounding losses that accumulated into material user harm.

**Remediation Notes**

For liquidation transfers, check available pool balance before transferring and fall back to seizing share tokens when insufficient underlying is available. For borrow-share-based repayment checks, use a slippage tolerance rather than an exact equality, or accept shares directly as the unit rather than converting from an amount.

---

### Accounting Share Mismatch (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Supply and borrow share totals are modified by multiple code paths (supply, borrow, repay, withdraw, liquidate, treasury mint, interest accrual) and any path that misattributes a sign or targets the wrong token causes a persistent imbalance
- Treasury share minting from accrued fees should increase total supply shares; inverting the sign causes a supply deficit that prevents the last suppliers from withdrawing
- Liquidation protocol fees are transferred out of the pool as tokens but the corresponding collateral supply shares are not reduced by the fee amount, creating a divergence between share liabilities and token assets
- `balanceOf` calls during position opening may query the wrong token (underlying vs. vault share token) when a wrapped or vault-based collateral type is used

**Detection Heuristics**

- For every function that mints treasury shares, verify the operator is `+=` not `-=` on the total supply counter
- For liquidation fee transfers, verify that shares are burned for the combined amount (collateral to liquidator + protocol fee), not just the liquidator's portion
- Search for `balanceOf(address(this))` calls in complex position-opening flows and trace whether the queried token matches the token actually held by the contract at that point
- After any "full" operation (full repay, full liquidation, full withdrawal), verify that the resulting balance is truly zero and that flags like `setBorrowing(false)` are conditioned on a zero-balance check, not set unconditionally

**False Positives**

- Rounding remainder of 1 wei in full repayment that is absorbed by protocol design
- Accounting mismatches that are display-only and do not affect token transfer amounts or solvency invariants

**Notable Historical Findings**

ZeroLend's `executeMintToTreasury` had a subtraction where addition was required, causing a progressive reduction of total supply shares each time fees were claimed; suppliers who remained in the pool long enough could not withdraw because share totals had been driven below zero. The same protocol's `_burnCollateralTokens` during liquidation did not account for the liquidation protocol fee amount in the share burn, so the pool held fewer tokens than shares represented after every fee-paying liquidation. Blueberry Update's `openPositionFarm` queried `uToken.balanceOf` instead of `vault.balanceOf`, depositing zero collateral while the vault tokens sat uncollateralized in the contract.

**Remediation Notes**

Add invariant assertions in test suites that verify `totalSupplyShares * liquidityIndex >= totalPoolAssets` after every operation. Flag any arithmetic operation on `totalSupplies.supplyShares` or `totalSupplies.debtShares` for manual sign review.

---

### Bad Debt and Protocol Insolvency (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- No minimum borrow amount is enforced in USD or ETH terms, allowing dust positions where the liquidation bonus is smaller than the liquidator's gas cost
- Minimum deposit checks can be bypassed by depositing above the minimum and then withdrawing down to dust, after which borrowing against the remaining collateral is unrestricted
- After a full liquidation where seized collateral is worth less than the outstanding debt, the remaining debt is left on the position with no socialization mechanism, and bad debt continues to accrue interest
- Protocol pauses, collateral parameter changes (LTV reductions, liquidation threshold changes), or oracle failures create windows where undercollateralized positions cannot be liquidated

**Detection Heuristics**

- Verify that both the per-transaction borrow amount and the resulting total position borrow value are checked against a minimum USD threshold after every borrow
- Check whether the minimum deposit enforcement function can be circumvented: is there a corresponding minimum check on withdrawal that prevents leaving sub-minimum collateral?
- Search for post-liquidation code: if `remainingDebt > 0` and `collateralValue == 0`, is the debt zeroed and distributed, or does it remain as phantom debt?
- Audit collateral parameter change functions for instant application without grace periods; a governance-executed LTV reduction should not immediately trigger mass liquidations

**False Positives**

- Protocols with an insurance fund or treasury backstop explicitly sized to absorb bad debt
- Bad debt socialized via liquidity index reduction at the time it arises, not deferred
- Protocols that operate on a single collateral type with stable oracle prices where bad debt risk is structurally bounded

**Notable Historical Findings**

Wise Lending had no minimum borrow amount, allowing the creation of positions too small to liquidate profitably; the resulting bad debt gradually increased the utilization ratio, distorting interest rates for all borrowers. JPEG'd had bad debt positions that continued compounding interest indefinitely rather than being frozen, causing the total debt figure to diverge from realizable value. INIT Capital lacked a mechanism to handle partially repaid bad debt after liquidation, leaving undercollateralized residual positions in an unliquidatable state. BendDAO's insolvency risk was compounded by never handling bad debt at all, meaning accumulated bad debt was an invisible liability socialised entirely onto the last suppliers to withdraw.

**Remediation Notes**

Implement a bad debt write-off path triggered at the end of any liquidation that leaves the position with zero collateral: zero out the remaining debt shares, reduce total debt shares by the same amount, and emit a bad debt event. Enforce minimum position size in both USD value and share terms to prevent dust positions from accumulating.

---

### Liquidation Logic Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Liquidation accounting must atomically update supply shares, borrow shares, interest rates, and liquidity indices; any partial update leaves the protocol in an inconsistent intermediate state
- Interest rate recalculation depends on utilization, which depends on the post-liquidation debt and supply totals; calling `updateInterestRates` before completing share burns produces stale utilization
- Liquidation of a position whose NFT or token collateral requires a transfer to the liquidator can be DoSed if the pool's available balance of that collateral asset has been depleted
- A borrower can front-run their own liquidation by repaying a minimal amount, invalidating the liquidator's pre-computed parameters

**Detection Heuristics**

- In `executeLiquidationCall`, verify the call ordering: (1) calculate amounts, (2) burn debt shares, (3) burn collateral shares including protocol fee portion, (4) transfer tokens, (5) update interest rates with the correct post-state
- Check that `setBorrowing(false)` or equivalent debt flag clearing only executes when actual debt balance is zero, not when the intended repayment amount equals the pre-computed debt
- Verify that liquidation of positions still accruing rewards resets or transfers the reward accumulator for the liquidated user; if not, the liquidated user continues receiving rewards on collateral they no longer hold
- For protocols with NFT collateral, check the `lockerAddr` or equivalent linkage is cleared on liquidation to prevent the NFT from being locked in an unrecoverable state

**False Positives**

- Protocols where liquidation seizes aToken/share representations rather than underlying tokens, which are unaffected by pool balance DoS
- Protocols with a maximum partial liquidation cap that bounds the seized amount to available balance, gracefully handling partial liquidation when full is impossible

**Notable Historical Findings**

ZeroLend had at least five distinct liquidation accounting errors in a single audit cycle: the collateral share burn omitted the protocol fee amount; interest rate updates occurred before debt share reduction; borrow rate was materially decreased after liquidation due to ordering; liquidated positions continued accruing rewards; and full liquidations left dust debt with the borrowing flag incorrectly cleared. BendDAO's `erc721DecreaseIsolateSupplyOnLiquidate` failed to clear the `lockerAddr` field, leaving liquidated NFT collateral locked. Wise Lending's liquidation could be front-run with a one-share repayment that caused the liquidator's parameter to exceed the updated borrow shares, reverting the transaction.

**Remediation Notes**

Treat the liquidation execution as a single atomic state machine: define the canonical step order explicitly and enforce it with intermediate assertions in test suites. Consider accepting shares directly as the liquidation unit to eliminate the share-to-amount calculation race condition.

---

### Interest Accrual Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Time-weighted interest accrual functions that use integer division for small time deltas can round the increment to zero while still advancing the checkpoint timestamp, permanently suppressing interest for sub-threshold intervals
- Rate parameters (APR, reserve factor, fee rate) changed by governance or admin do not trigger an accrual first, retroactively applying the new rate to the period that occurred under the old rate
- Bad debt positions continue compounding interest after collateral is exhausted, inflating the total debt figure and distorting utilization-based rate calculations
- Treasury share accrual uses a formula that includes treasury shares in the denominator when computing the supply interest rate, causing treasury to earn supply-side returns on top of its reserve-factor allocation

**Detection Heuristics**

- Check every setter that modifies `debtInterestApr`, `reserveFactor`, `borrowRate`, or equivalent: does it call `accrueInterest()` or `updateState()` before the assignment?
- For sub-second or sub-minute polling scenarios on L2, calculate the minimum time delta required to produce a non-zero interest increment at the protocol's rate; if callers can advance the timestamp without advancing the accrual, they can suppress interest
- Verify that bad debt positions (debt > collateral value) have their interest accrual explicitly paused or written off
- Check the supply interest rate formula: is the denominator `totalSupplyShares - accruedToTreasuryShares` (correct) or `totalSupplyShares` (causes double-dipping)?

**False Positives**

- Rate changes executed through a timelock where governance calls `updateState` as a prerequisite in the execution payload
- Minor compound-vs-linear divergence that creates a surplus smaller than the rounding unit
- Uncollateralized lending protocols that document best-effort interest accrual for very short intervals

**Notable Historical Findings**

JPEG'd had two related findings: `setDebtInterestApr` did not accrue pending interest first, allowing retroactive rate changes; and bad debt continued accruing interest after a position became insolvent, inflating the protocol's stated debt. ZeroLend's `updateState` accrued supply interest on `accruedToTreasuryShares` by including them in the total supply denominator, resulting in the treasury collecting more than the intended reserve factor. Accountable's open-term loan contracts had an interest accrual function where the timestamp advanced even when the calculated increment was zero, making frequent permissionless calls to `accrueInterest` an effective interest suppression attack. JOJO Exchange's JUSD borrow fee rate was computed with simple multiplication instead of a compound formula, understating fees materially over long periods.

**Remediation Notes**

For protocols where accrual functions are permissionless, guard them with a minimum interval check: if `block.timestamp - _accruedAt < MIN_ACCRUAL_INTERVAL`, return early without updating the timestamp. Emit an event when a bad debt position is frozen to provide observability for protocol health monitoring.

---

### Interest Rate Update Ordering (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Aave-style protocols maintain a cached state object passed through a transaction; `updateInterestRates` must be called with the post-operation cached state, not the pre-operation state
- In repayment flows, `updateInterestRates` is called before the debt shares are reduced, causing the rate model to observe higher utilization than the post-repayment reality and compute an elevated rate
- In withdrawal flows, supply-side rate recalculation before the supply is reduced overstates the remaining liquidity, computing a lower borrow rate than correct
- Governance-executed reserve factor changes that do not call `updateState` first retroactively apply the new factor to accrued but unsettled interest

**Detection Heuristics**

- In `executeRepay`, verify: (1) debt shares are reduced, (2) cache is updated with the new `debtShares`, and then (3) `updateInterestRates` is called - not (1) update rates, (2) reduce shares
- In `executeWithdraw`, the same ordering applies to supply shares
- In `executeLiquidationCall`, verify that `updateInterestRates` is called after the last token transfer (including fee transfers to treasury), not before
- For all admin setter functions touching rate model or reserve factor, verify `updateState` is called first

**False Positives**

- Protocols that intentionally compute rates at the start of each block and accept one-block-lagged rate effects as a design choice
- High-activity pools where a stale rate persists for less than one block before the next interaction corrects it

**Notable Historical Findings**

ZeroLend had at least four rate update ordering bugs in a single audit: repay updated interest rates before reducing debt shares; withdraw did not update rates after supply reduction; liquidation did not update rates after the fee transfer to treasury; and reserve factor changes were not preceded by a state update. BendDAO's pool configurator module allowed rate model changes without triggering an immediate rate recalculation, producing stale rates until the next user interaction.

**Remediation Notes**

Establish and document a canonical operation order as a code comment at the top of each execution function: (1) cache current state, (2) update indices, (3) modify balances, (4) recalculate rates. Enforce this order with a suite of unit tests that assert post-operation utilization equals the expected value.

---

### Position Health Check and Valuation Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Health factor computation includes pending rewards from third-party protocols; if any reward token lacks a configured oracle, the entire health check reverts, blocking all dependent operations (borrow, withdraw, liquidation)
- Protocols use weighted collateral (collateral value times LTV factor) for liquidation eligibility checks but bare collateral (full value without factor) for withdrawal checks, allowing users to withdraw from positions that are already liquidatable
- Position managers or proxy contracts that wrap core lending logic may lack health checks after position adjustments because they delegate to core functions that each check individually but not the aggregate post-adjustment state
- Borrow index staleness in health checks: if the index used to compute outstanding debt is not updated to the current block, health factors appear better than they are

**Detection Heuristics**

- Trace every path through `getPositionValue` or equivalent; identify all token loops and check whether a missing oracle for any token causes a hard revert versus a skip
- Compare the collateral valuation formula used in `checksWithdraw` versus `checksLiquidate`; they must use the same weighting
- For position managers accepting batched operations (adjust, add collateral, borrow), verify that a single health check is performed after all sub-operations complete, not between them
- Check oracle decimal validation: if the health factor formula uses price * amount, verify both are normalized to a consistent decimal base before comparison

**False Positives**

- Reward tokens explicitly excluded from collateral valuation by design, with a documented rationale
- Position adjustments that can only improve health (e.g., add collateral only), where a missing post-check is a gas optimization with no security impact

**Notable Historical Findings**

Blueberry Update's `getPositionValue` reverted when any reward token in the position had no oracle configured, DoSing all operations requiring a health check for affected users. Wise Lending had an inconsistency where liquidation eligibility used weighted collateral but uncollateralized withdrawal used bare collateral, allowing users to withdraw from positions that the liquidation module would consider eligible for seizure. ZeroLend's NFTPositionManager lacked a health check after position adjustments, allowing users to adjust their positions into undercollateralization without being blocked.

**Remediation Notes**

Wrap oracle calls in health check functions with a `try/catch` or a `hasOracle()` pre-check; missing oracles should cause the asset's contribution to be treated as zero value rather than reverting. Centralize the collateral weighting logic in a single library function shared by both the liquidation eligibility check and the withdrawal eligibility check.

---

### Reward Distribution Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Reward token lists in wrapped position contracts (WAura, WConvex) can have tokens added dynamically by the underlying protocol; rewards for newly added tokens may never be claimed if the wrapper's internal list is not synchronized
- Reward debt accumulators updated before the corresponding transfer means a failed transfer causes permanent reward loss for the user; the debt records the claim as satisfied even though no tokens were received
- Liquidation paths that seize collateral shares do not checkpoint and transfer the reward accumulator for the liquidated user; the liquidated user continues accruing rewards on positions they no longer hold
- Epoch boundary crossing in accumulator-based reward models uses the wrong epoch index, applying one reward rate to the entire cross-boundary period instead of prorating correctly

**Detection Heuristics**

- Check `removeRewardToken` functions: is `claimReward(token)` called for all users, or for the protocol's own position, before the token is removed from the list?
- Trace the reward claim flow: does `accountRewardDebt` update happen before or after the `safeTransfer`? Post-transfer update is correct; pre-transfer update loses rewards on failure
- After any liquidation that seizes collateral, check whether the reward accumulator for the seized collateral type is reset or proportionally transferred to the liquidator
- For epoch-based systems, identify the boundary crossing calculation: `nextEpoch = epoch + EPOCH_LENGTH` is correct; `nextEpoch = lastRewardTime + EPOCH_LENGTH` is typically wrong when `lastRewardTime` is not epoch-aligned

**False Positives**

- Reward claiming wrapped in `try/catch` that gracefully handles transfer failures by deferring rather than losing rewards
- Protocols with an admin rescue function that can recover stuck reward tokens for manual distribution to affected users

**Notable Historical Findings**

Blueberry Update had rewards stuck in the spell contract because the Convex spell claimed rewards to `address(this)` but only forwarded the primary token to the user, leaving all secondary reward tokens permanently locked in the contract. ZeroLend's NFTPositionManager continued distributing rewards to liquidated positions after collateral seizure because the reward accumulator was not reset during liquidation. Notional Leveraged Vaults updated `accountRewardDebt` before the reward transfer; when the underlying yield token was temporarily paused, users permanently lost their accrued rewards for that period. OlympusDAO had removed reward tokens become permanently unclaimable, causing loss for users who had not claimed before removal.

**Remediation Notes**

Adopt the `Effects-then-Interactions` pattern specifically for reward accounting: transfer tokens first, then update the debt accumulator using a `safeTransfer` that reverts on failure. Any reward token removal function must call a full claim for all outstanding balances before the removal takes effect.

---

### Treasury and Fee Accounting Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Treasury shares represent newly issued supply created from protocol-owned interest; their net effect on `totalSupplyShares` must be additive, not subtractive
- Liquidation protocol fees are a second collateral outflow from the pool in addition to the amount sent to the liquidator; both must be reflected in the supply share burn
- Reserve factor changes during an active pool must be preceded by a state update; applying a new factor retroactively to the unsettled accrual period overstates or understates the treasury's entitlement
- Fee calculation chains involving basis point division followed by multiplication are prone to intermediate truncation that silently zeroes fees for small pools

**Detection Heuristics**

- In `executeMintToTreasury` or equivalent, confirm the operation on `totalSupplies.supplyShares` is `+=` not `-=`
- In `executeLiquidationCall`, confirm shares are burned for `actualCollateralToLiquidate + liquidationProtocolFeeAmount`, not just `actualCollateralToLiquidate`
- Verify that `setReserveFactor` calls `updateState` or `accrueInterest` before modifying the parameter
- Check fee share calculations for division-before-multiplication: `feeAmount / (totalPool / totalShares)` loses precision; rewrite as `feeAmount * totalShares / totalPool`

**False Positives**

- Treasury shares held in a completely separate accounting ledger with no interaction with supplier share math
- Precision loss in fee calculations bounded to amounts smaller than the protocol's economic floor

**Notable Historical Findings**

ZeroLend's `executeMintToTreasury` subtracted accrued shares from total supply instead of adding them, a sign error that progressively starved the last suppliers of their withdrawal capacity. The same protocol's liquidation flow transferred the protocol fee to the treasury address without burning the corresponding collateral supply shares, creating a persistent asset-liability mismatch in the collateral market. ZeroLend also accrued supply interest on treasury shares by including them in the total supply denominator, causing treasury to compound above its entitled reserve factor allocation. Wise Lending had a fee precision loss from division-before-multiplication that allowed `claimFeesBeneficial` to permanently revert once accumulated rounding errors pushed the calculated fee shares below the transferable minimum.

**Remediation Notes**

Add a post-mint assertion: `totalSupplyShares after mint == totalSupplyShares before mint + mintedShares`. Add a post-liquidation assertion: tokens transferred out == supply shares burned times current index. Both are cheap to enforce in tests and prevent sign-error classes from surviving code review.

---

### Vault Share Inflation / First Depositor Attack (ref: fv-sol-2-c6)

**Protocol-Specific Preconditions**

- The vault has no minimum liquidity lock or dead shares mechanism, allowing the first depositor to hold exactly one share
- `totalAssets()` is computed from `token.balanceOf(address(this))` or a similar live balance query, making it manipulable by direct token donation without share minting
- After the share price is inflated to a large value per share, subsequent depositors receive zero shares due to rounding down, forfeiting their entire deposit to the first depositor
- Share price manipulation in uncollateralized lending protocols can also occur via partial redemption: filling part of a redemption queue without reducing the queue's tracked `totalValue` inflates the share price used to compute future requests

**Detection Heuristics**

- Check the first-deposit path: if `totalSupply() == 0`, are shares minted 1:1 with no dead share lock or minimum liquidity requirement?
- Verify `totalAssets()` implementation: does it use `balanceOf(address(this))` (vulnerable) or internal accounting variables (resistant)?
- Check whether `shares == 0` is asserted after the share calculation; a zero-share deposit silently forfeits the depositor's assets
- For protocols implementing ERC-4626, check for `_decimalsOffset()` override; if absent, virtual share protection may not be in use

**False Positives**

- Vaults using OpenZeppelin's ERC-4626 with a non-zero `_decimalsOffset()` (e.g., 3), which makes inflation attacks require at least `10**offset` times as much capital as the victim's deposit
- Vaults with a minimum initial deposit enforced in the constructor or `initialize` function
- Vaults using internal balance tracking rather than `balanceOf`, immune to donation inflation

**Notable Historical Findings**

JPEG'd's yVault was the first widely noted instance of this attack pattern: 1 wei deposit followed by a large token donation inflated the price per share, causing subsequent depositors to receive zero shares. Wise Lending's PendlePowerFarmToken had the same vulnerability specific to its PendleLP position token. ZeroLend's CuratedVaults were found not to use virtual shares, making them vulnerable to inflation despite awareness of the attack pattern at the time of deployment. Accountable's uncollateralized lending protocol had a partial redemption queue bug where partial fills did not reduce `totalValue`, allowing manipulation of the average share price used for subsequent requests.

**Remediation Notes**

Use OpenZeppelin ERC-4626 with `_decimalsOffset()` returning at least 3 for all new vault deployments. For protocols not using ERC-4626, adopt the Uniswap V2 minimum liquidity burn pattern: on first deposit, mint `MINIMUM_LIQUIDITY` shares to `address(0)` and subtract them from the user's allocation.

---

### External Protocol Integration Errors (no fv-sol equivalent)

**Protocol-Specific Preconditions**

- Balancer pool join and exit operations require `userData` encoded to match the specific `JoinKind`/`ExitKind` enum value; using the wrong kind causes silent mispricing or revert
- Convex and Aura wrappers expose `extraRewards(i)` arrays that grow dynamically; a wrapper contract that snapshots the array length at deployment will miss reward tokens added later
- External liquid staking tokens (stETH, weETH, rsETH) assumed to trade 1:1 with their underlying collateral cause collateral overvaluation when the peg weakens during market stress
- Pendle Principal Tokens (PT) assumed to redeem at exactly 1.0 of the underlying post-maturity cause overvaluation if the actual redemption rate diverges; function signatures in Pendle's router changed between V2 versions

**Detection Heuristics**

- For Balancer join/exit calls, trace the `JoinKind`/`ExitKind` enum value in `userData` and verify it matches the function semantics documented in Balancer's ABI
- Search for calls to `extraRewards(i)` or equivalent dynamic reward arrays; verify the contract tracks the array length and handles newly added entries
- Identify all hardcoded 1:1 peg assumptions for liquid staking tokens; replace with oracle-sourced price ratios
- For Pendle, EtherFi, Lido, and similar protocol integrations, verify function signatures against the deployed contract ABI at the target address, not against older documentation

**False Positives**

- Integrations where the external protocol version is pinned by an immutable address and the ABI is contractually frozen
- Peg assumptions bounded by an on-chain deviation check that reverts when the depeg exceeds a configurable threshold

**Notable Historical Findings**

Blueberry Update's Aura spell used `JoinKind.INIT` in the `userData` encoding when it should have used `JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT`, causing the pool join to fail silently or produce wrong BPT amounts. JPEG'd's `balanceOfJPEG` called `earned(address)` on Convex extra reward pools where the actual function signature was `earned()` with no parameter, causing reward balances to be permanently understated. Wise Lending's farm exit assumed stETH redeems 1:1 with ETH, overstating position value when closing a farm during periods of stETH depeg. Notional Leveraged Vaults assumed Pendle PTs redeem at exactly 1.0 post-maturity, causing mispriced collateral and incorrect health factor calculations.

**Remediation Notes**

Maintain a dedicated integration test for each external protocol that runs against a mainnet fork, calling the actual deployed contract at its current address. Pin all external protocol interface versions explicitly in the protocol's dependency manifest and include interface version validation in the integration's constructor.

---

### ERC-4626 Vault Compliance (ref: fv-sol-2-c6)

**Protocol-Specific Preconditions**

- External integrators (aggregators, yield routers, meta-vaults) rely on ERC-4626 invariants: `previewDeposit(assets) <= actual shares minted`, `previewRedeem(shares) <= actual assets returned`; violations cause silent losses for integrators
- `maxDeposit` and `maxWithdraw` returning non-zero values when the vault is paused causes integrators to submit transactions that revert, potentially bricking their logic
- Withdrawal fees not reflected in `previewRedeem` cause integrators that use the preview for slippage checks to accept worse outcomes than expected
- Inconsistent use of `totalAssets()` between `deposit` and `withdraw` paths (e.g., one includes accrued yield and the other does not) breaks the convertibility invariant

**Detection Heuristics**

- Verify the five ERC-4626 invariants mechanically: `previewDeposit >= deposit` (shares), `previewMint <= mint` (assets), `previewWithdraw >= withdraw` (shares), `previewRedeem <= redeem` (assets), `convertToShares(convertToAssets(x)) <= x`
- Check `maxDeposit`, `maxWithdraw`, `maxMint`, `maxRedeem` for pause and cap conditions; they must return 0 under any condition where the corresponding operation would revert
- Verify `totalAssets()` is consistent across all function paths; it must not return different values depending on call context
- Check ERC-4626 vaults used as CDP collateral: if the vault's `totalAssets` is manipulable, it constitutes an oracle manipulation surface

**False Positives**

- Vaults documented as intentionally non-standard with explicit deviation notes in the interface
- Rounding differences within the 1-wei tolerance the specification permits

**Notable Historical Findings**

Y2k Finance's vault was not ERC-4626 compliant despite inheriting the interface, causing integrators that relied on standard preview functions to compute incorrect expected outputs. Astaria's `ERC4626Router` had multiple functions that always reverted due to calling internal methods that had been removed from the underlying vault implementation. GoGoPool's `ggAVAX` had `maxWithdraw` and `maxRedeem` returning values larger than what was actually withdrawable, causing integrators to construct transactions that failed on execution.

**Remediation Notes**

Add a dedicated ERC-4626 compliance test suite that exercises every specified invariant against fuzz inputs, including edge cases at zero supply, maximum deposit cap, and paused state. Treat compliance test failures as build-blocking errors.

---

### Unsafe Token Interactions (ref: fv-sol-6)

**Protocol-Specific Preconditions**

- Lending protocols that accept multiple collateral types must handle tokens that do not conform to ERC-20: USDT requires approve-to-zero before a non-zero approval, some tokens do not return a boolean from `transfer`, and fee-on-transfer tokens deliver less than the requested amount
- Solmate's `SafeTransferLib` does not verify that the token address has deployed bytecode; calling `safeTransferFrom` on an address with no code succeeds silently, crediting a deposit that never arrived
- Fee-on-transfer tokens deposited as collateral credit the protocol-stated transfer amount rather than the amount actually received, creating a phantom collateral balance

**Detection Heuristics**

- Check whether `SafeTransferLib` is from Solmate (no code check) or OpenZeppelin `SafeERC20` (includes code check); for protocols accepting user-specified token addresses, the OpenZeppelin variant or an explicit code-length check is required
- Search for `IERC20.approve(spender, amount)` calls without a preceding `approve(spender, 0)`; for protocols that may be deployed with USDT as a supported collateral, this causes reverts on approval renewal
- For deposit functions that credit `amount` rather than `balanceAfter - balanceBefore`, verify the protocol explicitly excludes fee-on-transfer tokens or handles them with a balance-diff pattern

**False Positives**

- Protocols with an explicit collateral whitelist limited to known well-behaved tokens (DAI, WETH, WBTC, USDC)
- Protocols using OpenZeppelin `SafeERC20` throughout, which handles both the return-value problem and the code-existence check

**Notable Historical Findings**

Morpho had a vulnerability where Solmate's `SafeTransferLib` was used against a token that had not yet been deployed at the time of the call; the transfer succeeded silently, and the protocol credited the deposit, creating a claim against a non-existent balance. Notional and Connext both had USDT compatibility failures from direct `approve` calls without the zero-first reset. Backed Protocol's Papr Controller used an incorrect variant of `safeTransferFrom` that trapped fee tokens within the controller contract.

**Remediation Notes**

Establish a standard internal `_safeTransfer` library that (1) verifies code existence at the token address, (2) uses OpenZeppelin `SafeERC20`, and (3) applies a balance-diff check for collateral deposits. This library should be the sole approved method for all token interactions across the protocol.

---

### Signature and Replay Vulnerabilities (ref: fv-sol-4-c4, fv-sol-4-c10, fv-sol-4-c11)

**Protocol-Specific Preconditions**

- Lending protocols that accept signed commitments (e.g., for loan origination, collateral approval, strategy authorization) must include chain ID, contract address, nonce, and expiry in the signed digest
- EIP-712 struct hashes that omit fields from the type definition produce digests that are valid for more contexts than intended, allowing a signature issued for one purpose to authorize a different operation
- `ecrecover` returning `address(0)` for a malformed signature must be explicitly checked; failing to check allows any signature with invalid parameters to pass validation against a zero-address strategist or vault
- Meta-transaction and EIP-2612 permit flows that do not increment a nonce allow the same signature to be submitted multiple times

**Detection Heuristics**

- For every signature verification call, confirm the digest includes: `chainid`, `address(this)`, a nonce incremented on use, and a `deadline`
- Check the EIP-712 domain separator for all four required fields: name, version, chainId, verifyingContract
- Verify that `ecrecover` / `ECDSA.recover` return values are checked against both `address(0)` and the expected signer address in the same require
- For lending strategy or vault authorization signatures, verify the struct hash includes all parameters that distinguish one authorization from another (vault address, strategy type, rate limits)

**False Positives**

- Protocols deployed exclusively on a single chain with no cross-chain messaging and no future multi-chain plans
- Signatures that are inherently one-time-use through a consumed state flag independent of a nonce

**Notable Historical Findings**

Astaria had two signature-related highs: strategy signatures were forgeable because the struct hash omitted the vault address and deadline fields, allowing a valid signature for one strategy to be replayed against a different vault; and `ecrecover` was not checked against `address(0)`, allowing any malformed signature to pass validation. Biconomy had a cross-chain signature replay attack where signed meta-transactions lacked chain ID in the digest, allowing signatures intended for one chain to execute on another. SeaDrop's signed mint lacked replay protection, allowing the same permit to mint multiple times.

**Remediation Notes**

Use OpenZeppelin's `EIP712` base contract for domain separator construction; it correctly includes all four required fields and uses the current `block.chainid`, which prevents cross-chain replay even after a hard fork. Always use `SignatureChecker.isValidSignatureNow` rather than raw `ecrecover` to handle both EOA and EIP-1271 contract wallet signers correctly.

### Depeg of Pegged or Wrapped Asset Breaking Collateral Valuation (ref: pashov-13)

**Protocol-Specific Preconditions**

The lending protocol accepts pegged or wrapped assets as collateral (stETH, wstETH, WBTC, rETH, USDC-pegged stablecoins) and prices them using the underlying asset's oracle or assumes a fixed 1:1 exchange rate. No independent price feed exists for the derivative asset itself. During a depeg event, the collateral's actual market value diverges from the assumed value, overstating collateral backing and allowing undercollateralized borrows to persist or new ones to be opened.

**Detection Heuristics**

- Find all oracle price lookups for collateral assets and identify any that use the underlying asset's feed rather than a feed for the derivative itself (for example, an ETH/USD feed used to price stETH collateral).
- Identify hardcoded 1:1 ratios or assumptions such as `stETHPrice = ETHPrice` in collateral valuation or LTV computation.
- Check whether a configurable depeg threshold exists that triggers protective measures (LTV reduction, borrowing pause) when the derivative's price diverges from the peg beyond a tolerance.
- Verify that protocol documentation explicitly identifies the depeg assumption and its accepted risk level.

**False Positives**

- An independent price feed exists for the derivative asset (such as a dedicated stETH/USD feed) and is used in all collateral valuations.
- A configurable depeg tolerance triggers automatic LTV reduction or pool pause when the derivative/underlying ratio deviates beyond a defined threshold.
- Protocol documentation explicitly acknowledges and accepts depeg risk as a known limitation.

**Notable Historical Findings**

Wise Lending's farm exit assumed stETH redeems 1:1 with ETH, overstating position value when closing a farm during a period of stETH depeg. Notional Leveraged Vaults assumed Pendle PTs redeem at exactly 1.0 post-maturity, causing mispriced collateral and incorrect health factor calculations when redemption rates diverged.

**Remediation Notes**

Use a dedicated price feed for each derivative asset rather than assuming parity with the underlying. For assets where no on-chain feed exists, implement a deviation circuit breaker that compares a freshly queried exchange rate (from the protocol itself, such as `stETH.getPooledEthByShares(1e18)`) against the assumed value and pauses or adjusts LTV when the deviation exceeds a configured threshold.

---

### Small Positions Unliquidatable Due to Insufficient Incentive (ref: pashov-41)

**Protocol-Specific Preconditions**

Liquidation rewards are proportional to the collateral seized, meaning positions below a threshold USD size pay out a liquidation bonus insufficient to cover the gas cost of the liquidation transaction. No minimum position size is enforced at borrow time. Liquidators operating rationally skip these dust positions, allowing them to accumulate unchecked bad debt as collateral values decline.

**Detection Heuristics**

- Compute the minimum collateral value at which the liquidation bonus exceeds the estimated gas cost of a liquidation transaction at current gas prices. Verify the protocol enforces a minimum borrow size above this threshold.
- Check whether a minimum position size (`minBorrowAmount`, `dustThreshold`) is validated in `borrow` or `openPosition` entry points.
- Verify whether the protocol operates a liquidation bot that handles dust positions regardless of profitability.
- Review the protocol's bad debt socialization mechanism: is there an insurance fund, are losses haircut across depositors, or does bad debt accumulate indefinitely?

**False Positives**

- A minimum position size is enforced at borrow time set materially above the gas-cost break-even point for liquidation.
- The protocol operates a keeper network or liquidation bot that processes all undercollateralized positions regardless of profit.
- A socialized bad debt mechanism (insurance fund or depositor haircut) bounds the protocol's exposure to unliquidatable positions.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Enforce a minimum borrow size at origination that exceeds the gas cost of liquidation by a comfortable safety margin, accounting for gas price variability. When dust positions do accumulate (for example, through collateral value decline), implement a bad debt socialization mechanism or a protocol-operated liquidation that clears positions without requiring external liquidator incentive.

---

### Self-Liquidation Profit Extraction (ref: pashov-43)

**Protocol-Specific Preconditions**

The liquidation function does not prevent the borrower from liquidating their own position using a second address or a flash loan. The liquidation bonus or discount makes it profitable to deliberately allow a position to become slightly undercollateralized, liquidate it from a second address, and capture the incentive net of repayment cost.

**Detection Heuristics**

- Find the liquidation function and check for `require(msg.sender != borrower)` or equivalent that blocks self-liquidation.
- Compute whether the liquidation incentive minus the cost of being undercollateralized by the minimum threshold yields a net positive profit for the position owner.
- Check whether a flash loan can be used to fund the liquidation repayment, making capital requirements for self-liquidation effectively zero.
- Verify whether a liquidation penalty or fee applied to the borrower (not just a bonus to the liquidator) closes the profit window.

**False Positives**

- `require(msg.sender != borrower)` is present and validated for all liquidation entry points.
- The liquidation incentive is small enough (below gas cost threshold) that self-liquidation is net-negative after gas.
- A liquidation penalty charged to the borrower's collateral exceeds any discount or bonus the borrower would capture as liquidator.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Add `require(msg.sender != borrower)` to all liquidation functions. If `onBehalf` or proxy liquidation patterns are used, validate that neither the caller nor any direct beneficiary of the liquidation is the borrower. Calibrate the liquidation incentive to be large enough to attract liquidators in adverse conditions but small enough that self-liquidation is never profitable.

---

### Accrued Interest Omitted from Health Factor Calculation (ref: pashov-147)

**Protocol-Specific Preconditions**

The protocol's health factor or loan-to-value ratio is computed using the principal debt balance without first applying outstanding accrued interest. The health factor formula reads `collateralValue / principalDebt` rather than `collateralValue / (principalDebt + accruedInterest)`. Positions that are technically insolvent when interest is included appear healthy, delaying liquidations and accumulating bad debt.

**Detection Heuristics**

- Locate the health factor or LTV computation function. Check whether it calls an interest accrual function (`accrueInterest()`, `updateIndex()`) before reading the debt balance, or whether it reads a cached principal directly.
- Verify that `getDebt(user)` or equivalent returns the principal plus accrued interest, not principal only.
- Check whether the borrow index (interest multiplier) is applied to the stored debt shares before the health check compares against collateral value.
- Simulate a position that is healthy by principal alone but insolvent when interest is added; confirm the protocol's health check correctly identifies it as insolvent.

**False Positives**

- `getDebt()` already incorporates accrued interest through share-times-index multiplication before being returned.
- Interest accrual (`accrueInterest()`) is called unconditionally as the first statement of every health check function.
- The protocol compounds interest on every state-changing interaction, meaning the stored debt balance is always current.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Call interest accrual before any health factor or LTV check: place `accrueInterest()` at the top of `getHealthFactor()` and all liquidation trigger functions. Ensure `getDebt()` multiplies stored debt shares by the current borrow index rather than returning raw principal. Add an integration test that deposits collateral, borrows at the health limit, advances time to accrue interest, and confirms the position is correctly identified as liquidatable.

---
