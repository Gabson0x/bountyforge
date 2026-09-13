# Derivatives Protocol Security Patterns

> Applies to: perpetuals, futures, options, leveraged trading, GMX-style, dYdX-style, Perp Protocol-style, funding rate mechanisms, margin accounts, position management

## Protocol Context

Derivatives protocols - perpetuals, options, and leveraged trading venues - operate through continuous mark-to-market accounting, funding rate mechanisms, and real-time margin calculations that depend on accurate and fresh price data. Their state is unusually complex: open interest, funding rates, and fee accumulators are updated on every trade, and any arithmetic imprecision in these paths accumulates into systemic undercollateralization. The combination of high leverage and oracle dependency makes price manipulation and stale-price exploitation categorically more severe than in spot protocols, since a small price deviation can immediately render large positions undercollateralized or force incorrect liquidations.

The settlement and liquidation paths introduce additional surface area: vault share accounting for collateral deposits, withdrawal queue mechanics that can be griefed to lock user funds, and cross-margin position tracking that can desynchronize from the underlying collateral state if balance updates are applied out of order. Funding rate calculations that depend on a time-weighted skew between long and short open interest are particularly sensitive to manipulation, since they affect all open positions continuously rather than at discrete settlement events.

## Bug Classes

---

### Reentrancy via External Calls (ref: fv-sol-1)

**Protocol-Specific Preconditions**
Contract performs ETH transfers, ERC-721 `safeMint`, or token callbacks before updating position state, margin balances, or insurance reserves. The `nonReentrant` modifier is absent from the vulnerable function or is missing from sibling functions that share state, enabling cross-function reentrancy. Perpetuals and leveraged vaults are particularly exposed because position open/close flows often interleave token transfers with state writes.

**Detection Heuristics**
- Identify functions that transfer ETH via `.call` or tokens via `safeTransfer` before decrementing reserves or closing positions.
- Check for `_safeMint` calls in position NFT contracts where token ID counters or position arrays are updated after the mint callback fires.
- Verify that both `deposit` and `withdraw` functions carry `nonReentrant` when they share balance state.
- Look for initializer functions using a simple boolean guard rather than a modifier that includes reentrancy protection.
- Check pool upkeep or funding settlement functions that transfer fees to external addresses before updating `lastUpkeepTime` or `executionPrice`.

**False Positives**
- External call targets are immutable, audited contracts that cannot execute arbitrary logic.
- Checks-effects-interactions is followed: all state is finalized before any external call.
- Reentrancy guard covers all possible reentry paths including cross-function paths.
- The token in question is a standard ERC-20 without transfer hooks.

**Notable Historical Findings**
A reentrancy vulnerability in Tigris Trade's position NFT contract allowed an attacker to reenter `mint()` via the `onERC721Received` callback before the position array and token ID counter were updated, enabling duplicate position creation. In Hubble Exchange, `processWithdrawals` sent ETH before decrementing the reserve, allowing a malicious recipient to reenter and repeatedly extend the queue. Tracer's pool upkeep was vulnerable when fee tokens with callbacks were used, permitting reentry before `lastUpkeepTime` was written. OpenLeverage used `payable.transfer` for ETH sends in `doTransferOut`, which fails for contract recipients with non-trivial receive logic and can brick withdrawals.

**Remediation Notes**
Apply `nonReentrant` to all entry points sharing position or balance state, not just the most obvious one. Follow checks-effects-interactions strictly: decrement reserves and close positions before any external call. For position NFT contracts, increment token IDs and write position arrays before calling `_safeMint`. Store failed ETH withdrawals in a claimable mapping rather than assuming delivery.

---

### Rounding Direction and Precision Loss (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Protocol performs share/asset conversions, interest rate accruals, or liquidation repayment calculations using integer division. Rounding direction in deposit/redeem paths favors the user rather than the protocol, or division occurs before multiplication causing intermediate truncation. Virtual shares that accrue interest create compounding precision errors in lending vaults embedded in derivative protocols.

**Detection Heuristics**
- Identify all division operations in share-to-asset and asset-to-share conversions; deposits should round shares down, withdrawals should round assets up.
- Search for `(a / b) * c` patterns that should be `(a * c) / b`.
- Check `mulDivUp` vs `mulDivDown` consistency across paired functions (deposit/withdraw, mint/redeem, liquidate seize/repay).
- Look for `uint256(int256Value)` casts on values that can be negative.
- Verify that virtual/dead shares do not accrue interest or inflate share prices over time.
- Check boundary conditions where 1 wei produces 0 shares in subsequent depositor paths.

**False Positives**
- Rounding error is bounded to 1 wei per operation and accumulation is economically negligible.
- The protocol explicitly documents accepting a specific rounding direction with stated rationale.
- Virtual shares are designed to absorb rounding dust and do not compound.
- `mulDiv` with correct rounding direction is already used consistently across all paired functions.

**Notable Historical Findings**
Morpho had multiple rounding direction issues: supply cap calculations rounded down when they should round up, liquidation `repaidShares` rounded down leaving borrowers less healthy after liquidation rather than more, and redemptions in the Strata vault leaked value because `previewWithdraw` rounded in the wrong direction per ERC-4626 specification. Asymmetry Finance suffered precision loss in minimum output calculations because division occurred before multiplication, amplifying slippage in `calculateMinOut`. Float Capital had an unsafe `int256` to `uint256` cast in rebalance logic that produced a near-`2^255` value when the input was negative, corrupting subsequent arithmetic.

**Remediation Notes**
For liquidation paths, round repaid shares up so borrower health strictly improves after a liquidation event. For deposit paths into ERC-4626 vaults, use `previewWithdraw` rounding up and `previewDeposit` rounding down as the spec requires. Always multiply before dividing in minimum output calculations. Handle negative int256 values with explicit sign checks before casting to uint256.

---

### Funding Rate Manipulation (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol implements a funding rate mechanism based on market price versus oracle price or long/short open interest imbalance. A single trade's price is recorded as the hourly reference, enabling wash trading to skew the time-weighted average. Cumulative funding index accumulation uses the wrong reference index (current rather than previous), causing the rate to never accumulate. Insurance funding rates lack caps and can grow unboundedly as leveraged notional increases relative to pool holdings.

**Detection Heuristics**
- Check if market price fed into funding rate is derived from a single trade or a small sample rather than a volume-weighted accumulation.
- Verify cumulative funding rate logic uses `cumulativeRate[index] + instantRate` written to `index + 1`, not overwriting `index`.
- Look for unbounded growth in pool or insurance funding rate calculations without a `MAX_FUNDING_RATE` cap.
- Check if funding settlement is atomic across all markets in a single loop - this blocks with gas limit growth.
- Verify that validators or keepers cannot selectively delay order matching to profit from funding rate timing.

**False Positives**
- Market prices are sourced from external oracles rather than internal trades, making wash trading irrelevant.
- Funding rate caps are enforced at a higher protocol governance level.
- Markets settle independently and no atomic cross-market loop exists.
- The protocol has a small fixed number of markets that will never approach block gas limits.

**Notable Historical Findings**
Tracer had two distinct funding rate manipulation vulnerabilities where a single trade's price was used as the hourly reference, allowing an attacker to self-trade at extreme prices with zero net position risk to skew the funding rate. A separate Tracer finding showed the cumulative funding index was updated using the current index rather than the previous one, meaning the rate reset to zero on every update rather than accumulating. Hubble Exchange's insurance funding rate increased without bound as leveraged notional grew relative to pool holdings, eventually making funding costs economically absurd. Hubble also had a cross-market funding settlement function that would exceed block gas limits as market count grew.

**Remediation Notes**
Use volume-weighted price accumulation over the measurement interval rather than point-in-time trade prices. Write cumulative funding to `currentIndex + 1` derived from `currentIndex` to ensure proper accumulation. Cap the insurance or pool funding rate at a protocol-defined maximum. Settle funding per market independently to avoid gas limit denial of service as market count scales.

---

### Incorrect Fee and Reward Accounting (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol calculates trading fees for multiple order types (market open/close, limit, TP, SL, liquidation) using a branching fee schedule. Fee percentage is applied to the wrong base (pre-fee vs post-fee position size), or the wrong order type branch applies a flat fee. Reward and reserve token balances are conflated when the reward token is also a valid market asset. Keeper rewards are calculated in 18-decimal arithmetic but paid in 6-decimal settlement tokens.

**Detection Heuristics**
- Identify fee calculation branches that apply the same flat percentage across market close, TP, SL, and liquidation order types; each typically has a distinct fee tier.
- Check if overlapping fee components are each computed on the full position size rather than as a single combined percentage, causing double-counting.
- Look for sign errors in fee application: both long and short sides should be charged fees (subtracted), not one side credited.
- Verify that governance NFT reward distributions, referral payouts, and protocol treasury fees are each routed to the correct recipient.
- Check keeper reward calculations for decimal mismatch between 18-decimal gas cost computation and the settlement token's actual decimals.

**False Positives**
- A flat fee is intentionally applied to specific order types as a documented design choice.
- Fee overlap is intentional and the resulting margin calculation is correct by design.
- Protocol supports only one token with a known fixed decimal count.
- Reward and reserve tokens are structurally guaranteed to be different contracts.

**Notable Historical Findings**
Gainsnetwork applied a 5% flat fee to all non-market-close order types, overcharging TP and SL closures that should receive pair-specific fee rates. Tigris Trade's `_handleOpenFees` computed each fee component independently on the full position size and summed them, causing the margin calculation to treat fee amounts as if they did not overlap. Tracer had a sign error where the fee was added to the long side rather than subtracted, allowing one side to collect fees instead of paying them. Morpho's `claimToTreasury` sent the full underlying balance to the treasury including COMP rewards belonging to users when the underlying token was also the reward token.

**Remediation Notes**
Define distinct fee percentages per order type and apply them from a unified fee schedule rather than branching with hardcoded constants. Compute total fee as a single combined percentage of position size to avoid double-counting. Subtract fees symmetrically from both sides. Track reward token balances in a separate accounting variable from protocol reserves when the reward token coincides with a market asset. Scale keeper rewards to the settlement token's actual decimal precision before transfer.

---

### Position and Open Interest Accounting Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol tracks aggregate open interest per trading pair to enforce exposure limits and calculate price impact. OI is recorded using pre-fee position sizes rather than post-fee actual sizes, inflating the tracked exposure. Position increase validations pass the full new position size to exposure limit checks, double-counting existing OI. PnL settlement during leverage updates routes closing fees to the trader rather than the protocol vault.

**Detection Heuristics**
- Check if OI is added using the pre-fee or post-fee position size; OI should reflect the actual position size after fee deduction.
- Look for position increase validations that pass total new position size to `isWithinExposureLimits` instead of only the delta.
- Verify OI removal uses the same price denomination as OI addition (consistent collateral pricing).
- In leverage update PnL flows, verify closing fees are routed to the protocol, not included in the trader's net payout.
- Check for operator precedence bugs in leverage recalculation expressions involving position size, collateral, and a scaling constant.
- Verify `addOI` and `removeOI` are called symmetrically on all position open and close paths including limit order execution.

**False Positives**
- Protocol intentionally tracks gross OI including fees for risk management and has a separate limit check that uses deltas.
- Double-counting is mitigated at a higher layer that correctly applies delta-only checks.
- OI tracking is approximated and used only for informational display, not limit enforcement.
- Collateral is a stablecoin whose USD value does not meaningfully diverge.

**Notable Historical Findings**
Gainsnetwork had a critical vulnerability where decreasing position size via leverage update sent the closing fees to the trader rather than the diamond contract, effectively draining the protocol fee pool on every leveraged position modification. Tigris Trade recorded OI using the full pre-fee position size in `executeLimitOrder`, permanently inflating tracked exposure by the fee amount times leverage. A separate Gainsnetwork finding showed position increase validation passed the total new size to exposure checks rather than the incremental delta, incorrectly rejecting valid position increases near the limit. An operator precedence bug in `requestIncreasePositionSize` caused the new leverage to be calculated incorrectly due to missing parentheses around an addition before a scale multiplication.

**Remediation Notes**
Compute fees before recording OI and use the post-fee actual position size for all OI tracking. Pass only the size delta to exposure limit validation functions. Separate closing fee disbursement from trader PnL in settlement logic and explicitly route each to the correct recipient. Add parentheses around additive subexpressions before scale multiplications in leverage calculations.

---

### Missing Slippage Protection (ref: fv-sol-8)

**Protocol-Specific Preconditions**
Protocol performs token swaps via Uniswap, Curve, or Balancer on behalf of users using a hardcoded `0` minimum output. Slippage protection is present at a public interface but discarded by an internal swap wrapper. The public rebalance or swap function accepts both a user-specified `amountOutMinimum` and an `account` parameter, enabling any caller to trigger swaps on another user's behalf with zero slippage. Missing `deadline` in Uniswap V2/V3 router calls allows miners to delay execution until a favorable block.

**Detection Heuristics**
- Search for `exchange`, `exchange_underlying`, `swapExactTokensForTokens`, `exactInputSingle` calls and verify the minimum output argument is not `0`.
- Check if user-facing functions propagate a `minOut` parameter through to internal swap wrappers.
- Look for missing `deadline` fields in Uniswap router parameter structs.
- Identify public functions that accept both `amountOutMinimum` and `account` - this pattern exposes third-party accounts to frontrunning.
- Verify `calculateMinOut` does not compute division before multiplication which truncates to zero for small amounts.

**False Positives**
- Swaps occur within an atomic flash loan where the caller controls all steps and reverts on unfavorable output.
- Protocol uses a private mempool or commit-reveal scheme that prevents frontrunning.
- Swap size is trivially small relative to pool liquidity, making sandwich attacks unprofitable.
- Slippage protection is enforced by a parent contract that always wraps the internal function.

**Notable Historical Findings**
Asymmetry Finance's `VotiumStrategy` called Curve's `exchange_underlying` with hardcoded zero minimum output, leaving every CVX purchase vulnerable to sandwich attacks. UXD Protocol had a public `rebalanceLite` function that accepted a user-supplied `amountOutMinimum` alongside an `account` address, meaning any caller could trigger a swap against another account with zero slippage protection. A separate Asymmetry finding showed `calculateMinOut` computed division before multiplication, causing the minimum output to truncate to zero for typical deposit sizes, providing no effective protection. Tracer's insurance slippage reimbursement logic contained an error that allowed an attacker to exploit the mechanism to drain the insurance fund rather than compensate for slippage.

**Remediation Notes**
Never hardcode zero as a minimum output in production swap calls. Propagate caller-supplied `minOut` parameters through all internal wrappers without discarding them. Restrict rebalance functions to owner or keeper roles so they cannot be called against arbitrary account addresses. Include `block.timestamp` as the deadline in Uniswap router calls as a baseline; allow callers to provide shorter deadlines for time-sensitive operations.

---

### Withdrawal Queue Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Protocol implements a FIFO withdrawal queue where a failed ETH transfer (e.g., to a USDC-blacklisted address, or a contract without a `receive` function) permanently skips the entry rather than storing it for later claim. Minimum withdrawal amounts are too low to prevent queue spam. Multi-vault or multi-derivative unstake functions revert the entire operation when any single vault or derivative fails rather than isolating failures.

**Detection Heuristics**
- Identify sequential withdrawal queue implementations where a failed transfer causes the entry to be permanently lost rather than stored for a retry claim.
- Check minimum withdrawal amounts against the gas cost of queue processing to gauge spam feasibility.
- Look for multi-vault withdrawal loops where a single paused vault reverts the entire withdrawal.
- Verify that blacklistable tokens (USDC, USDT) used in queue-based push-withdrawal systems cannot block processing.
- Check for `break` statements in withdrawal loops that halt all processing on the first reserve shortfall.
- Verify that the queue length is bounded or that bounded batch processing exists.

**False Positives**
- An admin-callable skip or drain function can bypass stuck entries.
- Withdrawals use a pull pattern where users claim individually.
- Minimum withdrawal amount is high enough that spam is economically infeasible.
- Failed withdrawals automatically produce credit entries that users can claim separately.

**Notable Historical Findings**
Hubble Exchange had a `processWithdrawals` function that, on a failed ETH transfer, incremented the index and moved on, permanently losing the failed withdrawal with no recourse for the affected user. A separate finding showed the same queue was still subject to denial of service via spam even after a partial fix because the 5 VUSD minimum withdrawal was far too low to prevent cheap queue flooding. Strata's multi-vault `redeemRequiredBaseAssets` used `previewRedeem` without checking `maxWithdraw`, causing the entire withdrawal to fail if the targeted vault was paused even when other vaults had sufficient assets. Asymmetry Finance's unstake flow called each derivative's `withdraw` in a loop without try-catch isolation, meaning a single failing derivative bricked the entire unstake for all positions.

**Remediation Notes**
Store failed withdrawal amounts in a per-user claimable mapping rather than silently discarding them. Set minimum withdrawal amounts at a level that makes queue flooding economically infeasible relative to the attacker's capital cost. In multi-vault withdrawal flows, use `maxWithdraw` to check availability before attempting withdrawal and aggregate across vaults rather than requiring any single vault to satisfy the full amount. Wrap per-derivative calls in try-catch to isolate failures and route failed amounts to a pending mapping.

---

### Stale Chainlink Oracle Validation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol integrates Chainlink price feeds for margin calculations, liquidation thresholds, and funding rate computation without validating staleness, round completeness, or circuit breaker bounds. Using the deprecated `latestAnswer()` omits the round metadata needed for any validation. On L2 chains, the protocol does not check the sequencer uptime feed, allowing stale prices during sequencer downtime when `block.number` does not increment reliably.

**Detection Heuristics**
- Search for `latestAnswer()` calls - this is deprecated and provides no staleness or round completeness data.
- Search for `latestRoundData()` calls and verify `updatedAt` is compared against `block.timestamp` with a per-feed heartbeat threshold.
- Verify `answeredInRound >= roundId` to ensure the round is complete before using the price.
- Check for `minAnswer`/`maxAnswer` aggregator circuit breaker validation to detect price floor/ceiling clamps.
- Verify `startedAt > 0` to confirm the round has actually been initiated.
- On Arbitrum/Optimism deployments, check for sequencer uptime feed validation with a grace period after sequencer restart.

**False Positives**
- Protocol uses a TWAP that inherently smooths over brief stale intervals.
- Oracle is used only for non-critical display purposes and never influences on-chain state.
- Protocol wraps Chainlink calls in try-catch with a secondary fallback oracle.
- Heartbeat interval for the specific feed is extremely short and staleness is practically impossible.

**Notable Historical Findings**
Tigris Trade used `latestRoundData()` without any staleness check, round completeness check, or circuit breaker bounds, making liquidation prices manipulable during periods of oracle inactivity. Hubble Exchange had both a staleness bug and a separate missing `minAnswer`/`maxAnswer` circuit breaker check, meaning the protocol could use artificially floored prices during a market crash when the aggregator clamps to its minimum answer. Float Capital's market could become completely non-functional during Chainlink update gaps because the funding settlement function depended on fresh oracle data to proceed. Asymmetry Finance's AfEth deposits used oracle responses without validating the round, allowing deposits to proceed with stale or invalid price data that could misvalue collateral.

**Remediation Notes**
Validate `answeredInRound >= roundId`, `updatedAt + heartbeat >= block.timestamp`, `startedAt > 0`, and `answer > 0` on every `latestRoundData` call. Configure per-feed heartbeat thresholds appropriate to each feed's update frequency. Add `minAnswer`/`maxAnswer` bounds checks specific to the expected price range for each asset. On L2 deployments, gate all oracle reads behind a sequencer uptime check that also enforces a grace period after the sequencer resumes.

---

### ERC-4626 Vault Integration Issues (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol integrates ERC-4626 vaults for yield generation or collateral management and uses `previewRedeem`/`previewDeposit` for on-chain accounting decisions. Per the ERC-4626 specification, preview functions must not account for redemption limits such as vault pauses or caps, making them unreliable for actual withdrawal routing. Multi-vault architectures attempt to satisfy full withdrawal amounts from a single vault rather than aggregating partial amounts across available vaults. Slippage parameters in ERC-4626 wrapper functions are applied to a capped intermediate value rather than the user's original requested amount.

**Detection Heuristics**
- Search for `previewRedeem` or `previewDeposit` used to determine actual withdrawal or deposit amounts; verify `maxWithdraw`, `maxDeposit`, `maxMint`, or `maxRedeem` is checked first.
- Look for multi-vault loops that break on the first vault that can satisfy the full amount, ignoring the possibility of aggregating partial amounts.
- Check ERC-4626 wrapper mint functions for slippage parameter application order: slippage should apply to the original user-requested shares, not a capped intermediate.
- Verify that vault access controls such as whitelists cannot be bypassed via wrapper or bundler contracts.
- Check rounding direction: `previewWithdraw` should round up, `previewDeposit` should round up on shares side.

**False Positives**
- Protocol integrates a single vault guaranteed never to be paused or capped.
- Preview functions are used only for off-chain estimation, never for on-chain accounting.
- Wrapper contracts are intentionally designed to provide broader access as a documented protocol design choice.
- Rounding differences are bounded to 1 wei per operation and are economically insignificant.

**Notable Historical Findings**
Strata's `MetaVault` used `previewRedeem` to decide which vault to withdraw from, but `previewRedeem` ignores pause states per the spec, causing withdrawals to revert when a vault was paused even though other vaults had sufficient assets. A separate Strata finding showed `previewWithdraw` rounded in the protocol-unfavorable direction during yield phase redemptions, allowing value to leak from pUSDe holders to redeemers over many transactions. Morpho's ERC-4626 wrapper had a broken slippage check because `shares` was capped to `maxMint` before the `maxAssets` check, making the slippage protection apply to fewer shares than the user intended. Another Morpho finding showed that non-whitelisted users could deposit into permissioned vaults via the bundler by using the `erc20WrapperDepositFor` path, which did not check the original depositor's whitelist status.

**Remediation Notes**
Use `maxWithdraw` and `maxDeposit` to check vault availability before calling `withdraw` or `deposit`. In multi-vault withdrawal loops, aggregate partial amounts across all available vaults rather than requiring any single vault to satisfy the full request. Apply slippage checks against the original user-requested amount before any capping. Enforce whitelist checks on the original depositor identity, not the bundler or wrapper contract address.

---

### Fee-on-Transfer Token Incompatibility (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
Protocol accepts ERC-20 tokens for position collateral, pool deposits, or trade settlement and assumes the `amount` specified in `transferFrom` equals the amount received by the contract. Fee-on-transfer tokens such as PAXG, STA, or tokens with dormant fee switches (USDT, USDC) deliver less than the nominal transfer amount. Internal accounting credits the full `amount`, creating phantom balance that is not backed by actual holdings.

**Detection Heuristics**
- Search for `transferFrom()` calls where the `amount` parameter is directly credited to user state without measuring the actual balance change.
- Identify `deposit`, `supply`, `commit`, or `stake` functions that add `amount` to user balances after a `transferFrom`.
- Check if protocol documentation or token whitelists include tokens with known or potential fee-on-transfer mechanics.
- Look for DEX swap return values used for debt accounting without verifying the contract's actual post-swap balance.
- Check if `uncommit` or `withdraw` returns the full originally deposited amount rather than the actually-received amount.

**False Positives**
- Protocol explicitly restricts to a fixed token set known to have no transfer fees.
- Protocol documentation states fee-on-transfer tokens are not supported and the token whitelist enforces this at registration.
- Balance-before/balance-after patterns are already used consistently throughout all deposit paths.
- The fee mechanism on a specific token is dormant and governance has committed to not enabling it.

**Notable Historical Findings**
OpenLeverage's `closeTrade` with a V3 DEX path used the DEX's return value for debt repayment accounting rather than measuring actual received tokens, causing repayment to be overstated when the bought token had a transfer fee. A separate OpenLeverage finding in `uniClassSell` had the same root cause in the V2 sell path. Tracer's pool commitment functions credited the full committed amount to pending commit records without measuring what was actually received, meaning uncommit would attempt to return more than the contract held. Morpho's position manager accepted fee-on-transfer tokens without balance-difference measurement, causing position collateral to be overstated.

**Remediation Notes**
Measure the actual received amount by computing `balanceAfter - balanceBefore` around every `transferFrom` call and credit only that measured amount to user state. Store the actual received amount in any pending or committed records rather than the nominal parameter. For swap output accounting, measure the contract's output token balance delta rather than relying on the DEX return value.

---

### First Depositor Share Inflation Attack (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol implements a share-based vault or pool where share price is determined by `totalAssets / totalSupply`. The vault has zero deposits at initialization and does not enforce a minimum initial deposit or mint dead shares. An attacker can directly transfer tokens to the vault contract, inflating `totalAssets` without receiving shares, making subsequent depositors receive zero or very few shares. Virtual shares in lending protocols that compound interest create permanent bad debt or value leakage.

**Detection Heuristics**
- Check if the vault mints dead shares to `address(0)` or a burn address during initialization to anchor share price.
- Look for `totalSupply == 0` branches in deposit functions that lack minimum share requirements.
- Verify direct token transfers to the vault address cannot inflate `totalAssets()` without minting shares.
- Check if virtual/dead shares in embedded lending vaults accrue interest or earn yield.
- Look for ERC-4626 vaults missing `_decimalsOffset()` or equivalent virtual share offset protection.
- Verify share price cannot reach values where a typical deposit rounds down to zero shares.

**False Positives**
- Vault is initialized by the protocol deployer with a protected first deposit that anchors share price.
- Minimum deposit amount is large enough to make the donation attack economically infeasible.
- Vault uses OpenZeppelin ERC-4626 with `_decimalsOffset()` providing virtual share protection.
- Share pricing uses a separate oracle rather than `totalAssets / totalSupply`.

**Notable Historical Findings**
Asymmetry Finance's `AfEth` vault allowed an attacker to manipulate `preDepositPrice` by depositing 1 wei to receive 1 share, then donating a large amount directly to the contract, inflating the price-per-share so that subsequent depositors received zero shares and the attacker could redeem at a profit. Hubble's insurance fund suffered a similar attack where the first depositor could be priced out entirely. Morpho's virtual supply shares accrued interest from the total supply including the dead shares, meaning the unowned virtual shares claimed a growing percentage of total interest, effectively stealing from real suppliers over time. The complementary virtual borrow shares finding showed these unowned borrow shares compound interest as bad debt that can never be repaid, shrinking the withdrawable pool over time.

**Remediation Notes**
Mint a minimum quantity of dead shares to a burn address on the first deposit to anchor the share price and make inflation attacks prohibitively expensive. Alternatively, apply the OpenZeppelin ERC-4626 `_decimalsOffset()` pattern to create a virtual offset of `1e6` shares. Exclude virtual shares from interest accrual by tracking real shares separately and distributing interest only to the real share supply.

---

### Cross-Chain Messaging Failures (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
Protocol uses LayerZero, Wormhole, or a similar messaging layer to synchronize position state, bridge collateral, or relay funding operations across chains. The protocol assumes address symmetry (same address on both chains) without accounting for account abstraction wallets or multisigs. LayerZero's default blocking delivery model means a single malformed or oversized message permanently blocks all subsequent messages on that pathway. Amount parameters do not account for dust removal applied by the OFT layer before minimum amount checks.

**Detection Heuristics**
- Check if LayerZero `_send` calls validate the `_toAddress` length - an oversized payload causes the destination to run out of gas inside the try-catch, triggering the blocking failure mode.
- Look for cross-chain NFT bridges where burn-on-source and mint-on-destination are not atomically guaranteed and no retry or recovery mechanism exists.
- Check if cross-chain operations hard-code `msg.sender` as the destination address without allowing the user to specify a different destination for non-EVM or AA wallet use cases.
- Verify amount parameters account for OFT dust removal before applying minimum amount checks.
- Check if access control restrictions enforced on the direct path are also enforced on the cross-chain composer path.

**False Positives**
- Protocol operates on a single chain and cross-chain messaging is not used.
- Address symmetry is guaranteed because the protocol only supports EOAs on EVM-compatible chains.
- Dust amounts are economically negligible and failed operations can be trivially retried.
- The messaging layer provides non-blocking delivery guarantees.

**Notable Historical Findings**
UXD Protocol had a high-severity finding where an attacker could pass an excessively large `_toAddress` in `OFTCore.sendFrom`, causing the destination transaction to run out of gas and permanently block all subsequent LayerZero messages on that channel due to the default blocking behavior. Tigris Trade's cross-chain NFT bridge could mint duplicate NFTs with the same token ID on different chains if message delivery failed after the source burn but before the destination mint. Brix Money had three related cross-chain issues: enforced address symmetry breaking account abstraction wallets, minimum amount checks failing after OFT dust removal, and a cross-chain deposit path through the composer that bypassed staking restrictions enforced on the direct path.

**Remediation Notes**
Validate `_toAddress` length with a strict maximum before passing to the LayerZero send function. Allow users to explicitly specify a destination chain address rather than hard-coding `msg.sender` to support AA wallets and multisigs. Apply dust removal to the minimum amount threshold before comparing against the post-dust-removal send amount. Enforce all access control restrictions on cross-chain entry points using the same checks applied to direct entry points.
