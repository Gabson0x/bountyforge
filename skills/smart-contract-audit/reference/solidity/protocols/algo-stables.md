# Algorithmic Stablecoin Security Patterns

> Applies to: algorithmic stablecoins, rebase tokens, seigniorage stablecoins, uncollateralized stablecoins, Terra/LUNA-style, Ampleforth-style, peg maintained purely through mint/burn mechanics

## Protocol Context

Algorithmic stablecoins maintain their peg through programmatic supply adjustment tied to on-chain price signals rather than explicit overcollateralization. Rebalancing logic, epoch tracking, and minting authorization are the three principal failure surfaces: rebalancing must read manipulation-resistant prices; epoch counters must advance unconditionally regardless of user activity; and mint/burn operations must be strictly gated to authorized actors. Because peg defense depends on real-time market price rather than idle collateral, any attacker who can move the reference price before a rebalance can redirect protocol capital in a single transaction.

Seigniorage and rebase designs introduce epoch-synchronized reward accounting where multiple state variables must advance together. Stale epoch state, misaligned accumulator updates, and governance vote manipulation affecting emission parameters all become exploitable when the peg invariant is fragile enough that a single large attack can break the feedback loop entirely. The structural reliance on AMM pool prices rather than deep external feeds makes flash-loan-driven oracle manipulation a near-universal precondition for the highest-severity bugs in this category.

## Bug Classes

---

### Missing Access Control on Mint/Burn (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Critical supply-management functions (mintRebalancer, burnRebalancer, liquidateFrom, setOracleAddress) are callable by any address. The function was intended to be restricted to a specific rebalancer, admin, or position owner role but the modifier is absent. The unrestricted function can alter total supply, collateral ratios, or user positions directly.

**Detection Heuristics**
Search for `public` or `external` functions that modify mint, burn, liquidate, or oracle configuration state without access control modifiers. Compare function naming conventions and inline comments against the actual modifier list. Look for functions accepting an arbitrary `from` address for operations that should be self-initiated. Check whether modifier declarations exist elsewhere in the contract but were not applied to recently added or refactored functions.

**False Positives**
Functions that are intentionally permissionless by design (e.g., permissionless liquidation with correct incentive alignment). Access control enforced at the calling contract layer. View/pure functions with no state modification.

**Notable Historical Findings**
USSD's mintRebalancer and burnRebalancer were missing the onlyRebalancer modifier, allowing any caller to inflate or deflate the token supply at will. MCDEX Mai Protocol allowed any address to call liquidateFrom on behalf of any account, enabling force-liquidation of healthy positions with proceeds redirected to an arbitrary address. Fei Protocol's EthCompoundPCVDeposit lacked a recovery function for stranded ETH, a softer access control gap that locked protocol-owned funds.

**Remediation Notes**
Apply role modifiers (onlyRebalancer, onlyOwner, onlyGovernance) to all supply-changing and configuration functions. For permissionless liquidation flows, ensure the liquidator receives a reward but cannot redirect collateral proceeds; verify the position's collateral ratio before permitting the call.

---

### AMM/DEX Price Manipulation via Flash Loans (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol reads on-chain price from an AMM pool using instantaneous spot price (Uniswap V3 `slot0`, Uniswap V2 reserve ratios) rather than a time-weighted average. Flash loans of the governance or collateral token are available. The manipulated price triggers rebalancing, minting, or collateral valuation in the same block.

**Detection Heuristics**
Search for `slot0()` calls used in price calculations that feed into on-chain decisions. Look for `getReserves()` used directly as a price oracle without TWAP protection. Check if the price source feeds into rebalancing, minting, liquidation, or collateral valuation logic within the same transaction. Verify whether a TWAP oracle (`observe()`) is used instead of spot price.

**False Positives**
Price used only for off-chain monitoring or UI display. AMM pool with extremely deep liquidity where manipulation is economically infeasible. Protocol uses a TWAP with a sufficiently long window (30+ minutes). Additional circuit breakers exist (e.g., max price deviation per block).

**Notable Historical Findings**
USSD's rebalancer used Uniswap V3 `slot0` to determine whether to buy or sell collateral, allowing an attacker to flash-loan tokens, skew the pool price, trigger an erroneous rebalance, and profit from the resulting trade. A separate USSD finding showed that the reserve ratio of the Uniswap pair was used directly as price, trivially manipulable via a flash swap. Malt Protocol's livePrice variable could be manipulated across two consecutive blocks to trigger the defaultIncentive payout.

**Remediation Notes**
Replace `slot0` with Uniswap V3 `observe()` using a 30-minute TWAP window. Cross-check spot price against the TWAP and revert if deviation exceeds a protocol-defined threshold. For collateral valuation, rely exclusively on time-averaged prices and add circuit breakers for extreme deviations.

---

### Epoch and Share Accounting Gaps (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol uses epoch-based reward or state tracking where epoch advancement is triggered lazily (only on user interaction). State variables like `epoch[asset]`, `totalShares`, or `accRewardsPerShare` are advanced conditionally. When no user interaction occurs during one or more epochs, the epoch counter stalls, causing newly created bonds to record a stale `mintEpoch`.

**Detection Heuristics**
Search for `epoch[` assignments that are conditional on `totalShares > 0` or similar guards. Look for `createLock` or `createBond` functions that use `epoch[asset]` as a start-time marker. Check whether `accRewardsPerShare` arrays have gap-filling logic when epochs are skipped. Verify that `claim()` functions handle intermediate epochs with uninitialized accumulator values.

**False Positives**
A reliable keeper bot calls `distribute()` every epoch regardless of user activity. The protocol guarantees `totalShares > 0` at all times via protocol-owned permanent deposits. A dedicated `fillInEpochGaps()` function is always called before any reads.

**Notable Historical Findings**
Tigris Trade's BondNFT distribute() skipped epoch advancement when totalShares was zero, causing bonds created afterward to record a stale mintEpoch and expire far earlier than intended. Malt Protocol's RewardThrottle had multiple related issues: changing the timekeeper contract caused epoch discontinuities, and populateFromPreviousThrottle was exposed to front-run attacks that could corrupt cumulative APR calculations. An epoch without profit could also fail to carry its reward checkpoint into the next epoch.

**Remediation Notes**
Separate epoch advancement from the distribution guard: always advance the epoch counter regardless of totalShares, then conditionally distribute. Provide a `fillEpochGaps()` helper that initializes unset accumulator slots from the prior epoch before any claim calculation.

---

### Governance Vote Manipulation (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol has on-chain governance with token-weighted voting and delegation. Voting power snapshots are taken at or after proposal creation, and delegation or undelegation can occur while proposals are in a locked or pending state. Flash loans of governance tokens are available, or NFT-based voting power is derived from a `totalPower` variable that is not refreshed before snapshot creation.

**Detection Heuristics**
Check whether delegation and undelegation can occur within the same transaction or while a proposal is active. Verify that voting power snapshots are taken at a block strictly prior to proposal creation. Look for flash loan mitigations that check direct voting but not delegated voting. Check if NFT-based `totalPower` is recalculated before snapshots. Verify restricted users cannot bypass voting restrictions through delegation chains.

**False Positives**
Governance tokens are non-transferable or unavailable on lending markets. A timelock between delegation and voting prevents same-block attacks. Commit-reveal voting schemes prevent flash loan attacks. Quorum thresholds are based on total supply rather than active voting power.

**Notable Historical Findings**
Dexe suffered multiple governance manipulation vectors simultaneously: an attacker could combine a flash loan with delegated voting to reach quorum on a proposal, then undelegate and withdraw before the proposal finalized; separately, `totalPower` for NFT-based voting was never recalculated before the snapshot, allowing an attacker to artificially deflate the quorum denominator to near zero. A delegation chain bypass allowed restricted addresses to vote on proposals they were explicitly excluded from, and treasury voting power delegated to users could be turned against the protocol itself.

**Remediation Notes**
Prevent undelegation while a delegatee has active votes on unfinalized proposals. Force `recalculateAllNftPower()` before every snapshot. Apply a delegation cooldown (minimum one block) before tokens can be withdrawn. Validate delegation targets against restricted-user lists at delegation time, not only at vote time.

---

### Missing Slippage and Deadline Protection (ref: fv-sol-8)

**Protocol-Specific Preconditions**
Protocol performs token swaps through a DEX where `amountOutMinimum` is set to zero or `deadline` is set to `block.timestamp`. Minting functions accept no `minAmountOut` parameter, allowing sandwich attacks that profit from the mint price impact. Transactions can be delayed by validators or held in the mempool.

**Detection Heuristics**
Search for `amountOutMinimum: 0` or `amountOutMinimum = 0` in swap router calls. Look for `deadline: block.timestamp` which provides no protection since block producers set the timestamp. Check `exactInput`, `exactOutput`, and `swapExactTokensForTokens` calls for hardcoded zero slippage. Search for minting or rebalancing functions that lack a `minAmountOut` parameter in their external interface.

**False Positives**
Protocol uses a private mempool (e.g., Flashbots Protect) that prevents sandwich attacks. Swap is performed atomically within a larger transaction that has its own slippage check at a higher level. Token pair has liquidity depth making manipulation economically infeasible. Swap amount is trivially small dust.

**Notable Historical Findings**
USSD's UniV3SwapInput used `amountOutMinimum: 0` and `deadline: block.timestamp` on all rebalancer swaps, making every rebalance sandwichable at zero cost to the attacker. A separate USSD finding showed that mintForToken accepted no slippage parameter, allowing a front-runner to manipulate oracle-derived collateral values and force an unfavorable mint. Tigris Trade's limit order execution did not revalidate price bounds after position opening, allowing traders to lock in profits beyond the maximum PnL cap.

**Remediation Notes**
Expose `minAmountOut` and `deadline` as caller-supplied parameters on all swap and mint entrypoints. Validate deadline strictly against `block.timestamp` at the start of the function. For protocol-initiated rebalance swaps, derive `minAmountOut` from an on-chain TWAP with a defined maximum deviation.

---

### Oracle Stale Price Validation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol integrates Chainlink or another external price oracle for asset valuation in minting, trading, collateral assessment, or rebalancing. Oracle return values lack staleness checks, round completeness checks, or min/max circuit breaker bounds. Protocol prices WBTC using the BTC/USD feed without accounting for a potential WBTC/BTC depeg.

**Detection Heuristics**
Search for calls to `latestAnswer()`, which is deprecated and lacks staleness metadata. Search for `latestRoundData()` calls that discard `updatedAt`, `answeredInRound`, or `roundId` return values. Check for a maximum staleness threshold comparing `block.timestamp - updatedAt` against a heartbeat constant. Look for missing `minAnswer`/`maxAnswer` circuit breaker checks. Verify that the base and quote token ordering in oracle calculations matches the actual feed definition.

**False Positives**
Protocol uses a fallback oracle with its own freshness guarantees. Oracle data is used only for off-chain display. A separate circuit breaker pauses operations on stale data. A TWAP oracle is used alongside Chainlink as a cross-check.

**Notable Historical Findings**
Multiple USSD oracle integrations were found critically broken in a single audit: StableOracleDAI returned a price with incorrect decimal precision, the base/rate token pair was inverted producing a reciprocal price, and none of the oracle wrappers validated staleness. Additionally, pricing WBTC via the BTC/USD Chainlink feed would leave the protocol exposed to a WBTC depeg event. Tigris Trade and Fei Protocol both had Chainlink integrations that used `latestRoundData()` without checking `updatedAt` or `answeredInRound`.

**Remediation Notes**
Use `latestRoundData()` and validate all five return values: positive price, non-zero `updatedAt`, freshness within the feed heartbeat, `answeredInRound >= roundId`, and price within `minAnswer`/`maxAnswer` bounds. For wrapped assets (WBTC, stETH), use a dedicated depeg-aware oracle or add a secondary price deviation check. Normalize all oracle outputs to a consistent 18-decimal basis before use.

---

### Reentrancy via ERC721 Mint Callback (ref: fv-sol-1)

**Protocol-Specific Preconditions**
Contract uses `_safeMint()` to mint ERC721 position or bond tokens and updates state mappings after the mint call rather than before. No `nonReentrant` modifier is applied. The `onERC721Received` callback on the recipient contract can re-enter the minting function and observe inconsistent state (e.g., duplicate position IDs, uninitialized trade records).

**Detection Heuristics**
Search for `_safeMint` calls followed by state-modifying operations (the callback enables reentrancy). Look for `transfer`, `transferFrom`, `call{value:}`, or `send` followed by state updates. Check if functions performing external calls have `nonReentrant` or equivalent guard. Search for cross-contract calls that occur before local state changes.

**False Positives**
External call target is a trusted immutable contract with no callback capability. `nonReentrant` is applied at a higher-level entry point that calls the vulnerable internal function. Token being transferred does not support callbacks (standard ERC20 without ERC777 hooks).

**Notable Historical Findings**
Tigris Trade's Position contract called `_safeMint` before updating `_openPositions`, `initId`, and `_trades`, allowing an attacker's contract to re-enter during `onERC721Received` and mint duplicate tokens with colliding position IDs, resulting in theft of funds. Dexe governance NFTs used `_mint` instead of `_safeMint`, which avoids the callback reentrancy but permanently locks tokens if the recipient is a contract without ERC721 receiver support. MCDEX Mai Protocol had reentrancy possibilities in deposit, withdraw, and insurance fund functions.

**Remediation Notes**
Apply the checks-effects-interactions pattern: update all state mappings before any external call including `_safeMint`. Apply `nonReentrant` on every public minting and withdrawal function. Use `_mint` only when recipients are guaranteed to be EOAs; otherwise use `_safeMint` with all effects completed first.

---

### Reward Distribution Accounting Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol has a staking, locking, or bonding mechanism distributing rewards via an accumulated-rewards-per-share pattern. `totalShares` is decremented only on explicit user release rather than automatically on expiry, causing expired shares to dilute active participants. `rewardDebt` is computed using the total `virtualAmount` rather than the delta during partial withdrawals.

**Detection Heuristics**
Check if `totalShares` is decremented only upon user-triggered release rather than on expiry. Look for `rewardDebt` calculations during partial withdrawals and verify the delta (not the total) is used. Search for `distribute()` or reward accumulation functions that skip epoch updates when `totalShares == 0`. Verify that reward coefficient changes do not retroactively affect already-active reward periods.

**False Positives**
A keeper bot reliably releases expired positions within the same epoch they expire. `totalShares == 0` is impossible due to protocol-owned permanent stakes. Reward debt calculation uses a different but mathematically equivalent formulation. Distribution is event-driven rather than epoch-driven.

**Notable Historical Findings**
Tigris Trade's BondNFT had at least 34 findings related to reward distribution across two audit rounds: expired bonds remained in `totalShares`, diluting rewards for active stakers; a malicious user could exploit this to steal all assets in the BondNFT contract. Fei Tribechief used `user.virtualAmount` instead of the withdrawal delta `virtualAmountDelta` when computing `rewardDebt` during partial withdrawals, causing systematic over- or under-accounting. Malt Protocol's LinearDistributor set `previouslyVested` to `currentlyVested` even when the actual distributed amount was capped by available balance, permanently losing the unclaimed remainder.

**Remediation Notes**
Decrement `totalShares` at bond expiry, not only at user-initiated release. For partial withdrawal `rewardDebt` updates, use the proportional delta. Always advance epoch tracking before distributing rewards, even when `totalShares` is zero. Test reward accounting invariants (sum of pending rewards equals total undistributed balance) as part of the test suite.

---

### Stale Protocol State Usage (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol caches aggregated data (collateral ratios, collateral deficits, NFT voting power totals, epoch counters) in state variables that are updated lazily. Critical functions read these cached values without triggering a refresh. Multiple contracts share state that must be synchronized before derived values are trusted.

**Detection Heuristics**
Search for functions that read aggregated state (deficit, ratio, totalPower, epoch) without calling an update or sync function first. Look for multi-contract architectures where one contract caches data from another without refreshing before use. Check whether `stabilize()`, `rebalance()`, or similar critical functions call `sync()` or `update()` on their data sources. Look for NFT power calculations using snapshot values without forcing a recalculation.

**False Positives**
A keeper bot reliably updates state every block or every epoch. The staleness window is bounded and its impact is negligible relative to decision thresholds. The function has explicit freshness checks (e.g., `require(lastUpdated == block.number)`). State is immutable or changes only through governance.

**Notable Historical Findings**
Malt Protocol's `stabilize()` read `swingTraderCollateralDeficit` and `swingTraderCollateralRatio` from a global implied collateral service that was not synchronized at the start of the call, causing stabilization decisions to be based on outdated deficits and potentially over-buying Malt. A companion finding showed `_distributeProfit` had the same staleness issue. Dexe's proposal creation read `erc721Power.totalPower()` for quorum calculation without first calling `recalculateTotalPower()`, allowing the denominator to reflect a stale and potentially manipulated value.

**Remediation Notes**
Call `sync()` or equivalent on all upstream state aggregators at the start of any function that derives critical values from them. Separate the epoch advancement logic into an internal `_advanceEpoch()` function that is called unconditionally before any distribution or accounting read.

---

### Token Decimal Mismatch (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Protocol interacts with multiple ERC20 tokens having different decimal precisions (USDC: 6, DAI: 18, WBTC: 8). Arithmetic operations assume a fixed 18-decimal basis without normalizing inputs. Oracle price feeds return values in a different decimal base than the token being priced. Cross-token calculations (collateral ratios, exchange rates, price conversions) are performed without explicit normalization.

**Detection Heuristics**
Search for hardcoded `10**18` or `10**(18 - decimals)` patterns that do not handle tokens with more than 18 decimals. Look for `from18()`/`to18()` conversion functions applied to amounts already in native token decimals. Check oracle integration code for mismatches between the oracle's return decimals and the expected scale. Identify inverted base/quote token pairs in price calculations (e.g., using ETH/DAI as DAI/ETH).

**False Positives**
Protocol only supports tokens with a known fixed decimal enforced by governance. Decimal conversion is handled by a well-tested library that covers all edge cases. Mismatch is in a view function used only for off-chain display.

**Notable Historical Findings**
USSD had at least seven decimal-related findings in a single audit: StableOracleDAI returned a price with an incorrect number of decimals; the base/rate token pair was inverted producing a reciprocal price; getOwnValuation contained arithmetic errors in the price calculation; SellUSSDBuyCollateral's DAI check was wrong; and amountToSellUnit was computed with an off-by-one decimal factor. Dexe's TokenSaleProposal implicitly assumed the buy token had 18 decimals, producing a total loss for buyers using USDC or USDT. Tigris Trade's deposit handler would revert on tokens with more than 18 decimals due to an underflow in the decimal scaling expression.

**Remediation Notes**
Implement explicit bidirectional normalization helpers (`normalizeAmount`, `denormalizeAmount`) that handle decimals both above and below 18. Validate all Chainlink oracle decimal assumptions at integration points. Add fuzz tests that exercise all supported collateral assets with their actual decimal configurations.

---

### Unsafe ERC20 Token Operations (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Protocol interacts with arbitrary or semi-arbitrary ERC20 tokens (USDT, fee-on-transfer tokens, deflationary tokens) as collateral or trading assets. Token interactions assume standard ERC20 return values, no transfer fees, and standard `approve` semantics. Protocol uses `approve()` without first resetting to zero for USDT-style tokens, or records the requested `amount` parameter rather than measuring the actual post-transfer balance.

**Detection Heuristics**
Search for `approve(` calls that do not first set allowance to zero. Look for `transferFrom` or `transfer` calls where the return value is unchecked and `safeTransfer` is not used. Check if the protocol records the `amount` parameter rather than measuring the actual balance change. Identify hardcoded assumptions that stablecoins maintain a 1:1 peg without oracle verification.

**False Positives**
Protocol explicitly documents and enforces that only standard ERC20 tokens are supported. A governance-maintained token whitelist excludes all non-standard tokens. Fee-on-transfer tokens are explicitly blacklisted. Protocol uses WETH exclusively and never interacts with raw ETH or non-standard tokens.

**Notable Historical Findings**
Tigris Trade used raw `IERC20.approve()` without first resetting to zero, causing permanent failure when USDT was used as collateral because USDT's approve reverts if the current allowance is non-zero. A separate Tigris finding showed the protocol assumed stablecoins always equaled exactly $1, ignoring real depeg events. Dexe accepted fee-on-transfer tokens in distribution proposals, recording the requested amount rather than the actual received amount, making such proposals permanently under-funded. A Dexe DAO Pool finding showed tokens could be allocated in a tier sale without the DAO actually transferring them, due to an unchecked return value.

**Remediation Notes**
Use `safeApprove(spender, 0)` followed by `safeApprove(spender, amount)` for USDT compatibility, or prefer `safeIncreaseAllowance`. Measure actual received amounts via balance deltas for all `transferFrom` calls. Verify stablecoin peg via oracle with configurable deviation bounds before accepting as collateral at face value.

---

### Unsafe NFT Minting and Transfer Operations (ref: fv-sol-1)

**Protocol-Specific Preconditions**
Protocol mints ERC721 position or bond tokens using `_mint()` instead of `_safeMint()`, or uses `_safeMint()` but performs state changes after the mint. Batch transfer functions claim to be "safe" but internally call `transferFrom` or `_transfer` rather than `safeTransferFrom`. NFT recipients may be smart contracts without `IERC721Receiver` support.

**Detection Heuristics**
Search for `_mint(` calls in ERC721 contracts that should use `_safeMint(`. Look for `_safeMint` calls where state changes occur after the mint, violating checks-effects-interactions. Search for functions named `safeTransfer*` that internally use `transferFrom` or `_transfer`. Verify that `_safeMint` callers have `nonReentrant` applied.

**False Positives**
Recipient is always a verified EOA by design. Recipient address is validated against a whitelist of known-safe contracts. Reentrancy from `_safeMint` cannot cause meaningful state manipulation. Minting function has `nonReentrant` already applied at an appropriate level.

**Notable Historical Findings**
Tigris Trade's Position contract updated `_openPositions` and `_trades` after `_safeMint`, allowing a malicious `onERC721Received` callback to re-enter and produce duplicate position IDs, which was confirmed as a fund-theft vulnerability in two separate audit rounds. In the same codebase, `safeTransferMany()` had a misleading name: it used `_transfer()` internally instead of `safeTransferFrom`, silently skipping the receiver check for batch transfers. Dexe's governance NFT used `_mint()` instead of `_safeMint()`, which avoided the callback but caused permanent token loss if the recipient was a contract.

**Remediation Notes**
Apply `nonReentrant` to all minting functions. Update all state (position arrays, ID mappings, trade records) before calling `_safeMint`. Audit all batch transfer helpers for naming accuracy and ensure they call `safeTransferFrom` when the name implies it. Prefer `_safeMint` over `_mint` for all ERC721 tokens that may be received by contracts.
