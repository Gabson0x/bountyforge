# Privacy Protocol Security Patterns

> Applies to: privacy protocols, on-chain mixing, zero-knowledge proof systems, shielded pools, Tornado Cash-style, Aztec-style, zk-privacy applications

## Protocol Context

Privacy protocols maintain shielded state-balances, notes, commitments-that must remain consistent with the underlying token balances they represent. The key security invariant is that the public contract state never leaks information about individual users while still enforcing economic correctness: every withdrawal must correspond to a valid prior deposit, and the aggregate shielded balance must equal the aggregate deposited tokens. This dual requirement-cryptographic correctness and economic soundness-means that standard DeFi vulnerabilities (reentrancy, oracle manipulation, rounding) interact with privacy-specific concerns (proof malleability, nullifier handling, commitment ordering) in ways that are often more severe than in transparent protocols.

---

### Fee-on-Transfer Token Mishandling (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Privacy protocol supports arbitrary ERC-20 deposits and claims support for "any token pair"
- Internal shielded balance is credited the full nominal deposit amount, but the vault's actual token balance is less due to transfer fees
- Callback-based token intake patterns verify that exactly the expected amount arrived and revert for any shortfall, making fee-bearing tokens permanently unusable even if they are otherwise valid assets

**Detection Heuristics**
- Identify all `safeTransferFrom(sender, address(this), amount)` calls where `amount` is used directly to update internal shielded balances
- Look for `require(token.balanceOf(address(this)) >= balanceBefore + amount)` patterns that enforce exact amounts; these hard-revert for fee-on-transfer tokens
- Check privacy protocol whitepapers for claims of "any ERC-20 support" without a corresponding fee-on-transfer exclusion
- Find `_increaseInternalBalance(recipient, token, amount)` called immediately after `safeTransferFrom` without a balance diff measurement

**False Positives**
- Protocol maintains an explicit whitelist of supported tokens that excludes all fee-bearing assets
- Protocol clearly documents that fee-on-transfer tokens are unsupported and input validation enforces this
- The protocol only interacts with USDC, WETH, DAI, or other tokens with no transfer fee

**Notable Historical Findings**
Beanstalk's internal balance system (used by its privacy and composability features) credited users the full nominal amount on `LibTransfer` operations, but the actual token balance fell short by the accumulated fee on every transfer, creating a growing insolvency gap across the affected token pools. Timeswap's mint and convenience contracts reverted with "Insufficient token transfer" for any fee-on-transfer token because the callback verification enforced exact amounts, making those tokens permanently unusable in the protocol despite no explicit exclusion.

**Remediation Notes**
- Measure actual received amount as `token.balanceOf(address(this)) - balanceBefore` and use that value for all internal balance credits
- For callback-based systems, pass `actualReceived` to the verification step rather than the original `amount` parameter
- Alternatively, enforce the token whitelist at the smart contract level with an on-chain allowlist rather than relying on documentation

---

### Flash Loan Price Manipulation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Privacy protocol uses spot Curve pool balance ratios to detect collateral depeg rather than oracle-reported prices
- NFT-gated access to private participation rounds checks `nft.balanceOf(msg.sender)` at the time of the call rather than at a prior snapshot
- Liquidity valuation for collateral uses a spot AMM swap output (`getAmountOut`) rather than a TWAP or oracle-reported price

**Detection Heuristics**
- Identify collateral or depeg checks that compute a ratio from `curvePool.balances(i) / totalBalance` within the same transaction that could have those balances manipulated
- Search for `require(nft.balanceOf(msg.sender) > 0)` gates in time-sensitive participation functions
- Check if `router.getAmountOut` is used for any valuation that feeds into collateral, liquidation, or reward calculations
- Look for melt or burn-rate functions where the economic outcome depends on current token supply ratios

**False Positives**
- Protocol uses TWAP pricing exclusively for all collateral and depeg checks
- Protocol uses Chainlink feeds that cannot be influenced by within-block actions
- NFT balance gate uses a historical snapshot (`balanceOfAt(user, snapshotBlock)`) rather than current balance
- Flash-loan protection (same-block transfer restrictions) is in place

**Notable Historical Findings**
Reserve Protocol's `_anyDepeggedInPool` function measured Curve pool balance ratios at spot to determine if an asset had depegged; a flash loan could skew those balances beyond the deviation threshold, triggering a false depeg detection and locking collateral operations. Boot Finance's privacy-adjacent participation round used a live `nft.balanceOf` check that could be satisfied by flash-borrowing an eligible NFT for the duration of the transaction, bypassing the intended access restriction entirely. Reserve's `Furnace.melt` was vulnerable to sandwich attacks because the melt rate was computed from a spot price that could be moved by a large preceding swap.

**Remediation Notes**
- Replace spot balance ratio checks with Chainlink oracle comparisons per token to a peg price
- Replace live `balanceOf` gates with `balanceOfAt(user, snapshotBlock)` checks using a block snapshot captured before the participation window opens
- Use a TWAP from the specific pool (`oracle.consult(token1, amount, USDC, TWAP_PERIOD)`) rather than spot swap output for any liquidity valuation

---

### Front-Running Initialization and Setup Functions (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Proxy-based privacy protocol deploys an implementation and calls `initialize()` in a separate transaction, leaving a window for an attacker to front-run the initialization and claim ownership
- Pool or note-commitment initialization accepts a first-caller that can set the initial price ratio or interest rate with negligible capital, distorting all subsequent operations
- Approval-based group-buy contracts interact with USDT-style tokens that revert on non-zero to non-zero approval changes, permanently blocking all group operations after the first instance completes

**Detection Heuristics**
- Search for `initialize()` functions that are `public` or `external` without `initializer`, `onlyOwner`, or factory-enforced access control
- Identify proxy contracts where the implementation's `initialize()` is callable directly on the implementation address
- Look for first-minter or first-depositor paths that set critical pool parameters without minimum deposit requirements or locked minimum liquidity
- Check USDT (and similar token) approval sequences in group or shared contracts for the approve-without-zero-reset vulnerability that blocks second use

**False Positives**
- Initialization is called atomically within a factory `create` function in the same transaction as deployment
- `initializer` modifier from OpenZeppelin is applied and the implementation is also initialized in its constructor
- The front-running window exists but has no exploitable consequence because parameters are fixed by governance regardless of caller

**Notable Historical Findings**
Unlock Protocol's `PublicLock.initialize()` was `public` with no access control and no deployer check, allowing an attacker to front-run any deployment and claim the lock's creator role-effectively taking over the economic parameters of the newly deployed lock. Timeswap's pool initialization was front-runnable: an attacker could observe a pending `mint` transaction and insert their own `mint` with extreme asset/collateral ratios at minimal cost, permanently distorting the initial interest rate for the affected pool. Reserve Protocol suffered from multiple initialization-adjacent vulnerabilities where early users could manipulate the stakeRate and basketsNeeded/supply ratio by calling `issue` followed by `melt` before other participants entered.

**Remediation Notes**
- Call `_disableInitializers()` in every upgradeable implementation's constructor and deploy through a factory that initializes atomically
- Enforce a minimum initial deposit and burn `MINIMUM_LIQUIDITY` shares to `address(0)` on first mint
- For group contracts using USDT, reset approvals to zero and then re-approve at the start of each new group operation

---

### Incorrect Collateral Valuation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Collateral value computation omits external protocol exchange fees (Synthetix exchange fee, Lyra withdrawal fee) that would reduce the actual liquidation proceeds
- Withdrawal fee from an external LP is applied unconditionally in the valuation, but the external protocol only charges the fee under certain conditions (e.g., only when live option boards exist)
- Stablecoin collateral is valued at a hardcoded 1:1 peg without consulting an oracle, leaving the protocol exposed to depeg events
- Debt calculation uses principal-only balance (`isoUSDLoaned`) instead of the principal-plus-accrued-interest balance, allowing users to borrow against interest they already owe

**Detection Heuristics**
- Compare the collateral valuation function against the actual liquidation path on the underlying protocol; any fee or cost incurred in liquidation must be reflected in the valuation
- Search for conditional fee application logic and verify it matches the external protocol's actual fee schedule precisely
- Identify hardcoded `USDC = $1` or equivalent peg assumptions; require oracle validation for all stablecoins
- Check all debt read sites: does the code read `loanPrincipal` or `loanPrincipalPlusInterest`?

**False Positives**
- Fee discrepancy falls within the over-collateralization buffer, making the valuation error economically harmless
- Protocol intentionally undervalues collateral as a conservative safety measure
- External fee structure is fixed and immutable, making the valuation approximation reliably accurate

**Notable Historical Findings**
Isomorph's `Vault_Synths` priced Synthetix synthetic collateral at face value without deducting the Synthetix exchange fee that would be charged on liquidation, causing the protocol to believe collateral was worth more than its actual liquidation value and enabling under-collateralized positions. The Lyra vault variant incorrectly applied the withdrawal fee unconditionally, but Lyra only charges the fee when there are active option boards; this caused Lyra collateral to be systematically undervalued during quiet periods, blocking healthy users from accessing their full collateral value. A separate Isomorph finding showed that `isoUSDLoaned` (principal only) was used instead of `isoUSDLoanAndInterest` for total debt calculation, allowing borrowers to take out new loans against the outstanding interest they already owed.

**Remediation Notes**
- For each external protocol used as collateral, explicitly model every fee charged during liquidation and deduct it from the valuation
- Make fee application conditional on the same runtime conditions the external protocol uses (e.g., `optionMarket.getNumLiveBoards() != 0` for Lyra fees)
- Always use an oracle price for stablecoin collateral; never assume a 1:1 peg at the smart contract level

---

### Missing Access Control on Sensitive Functions (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Withdrawal function transfers tokens to `msg.sender` but only requires approval over a deposit NFT, not that `msg.sender` is the NFT owner
- Vesting function accepts any beneficiary address from any caller, enabling griefing attacks that fill the beneficiary's timelock array with dust entries and cause out-of-gas on legitimate claims
- Initialization function is `external` without access control and can be front-run between deployment and initialization

**Detection Heuristics**
- Identify external functions that transfer tokens to `msg.sender`; verify `msg.sender` is the NFT owner or rightful beneficiary, not merely someone who triggers the function
- Look for `timelocks[_beneficiary].push(...)` or equivalent unbounded array appends where `_beneficiary` is caller-supplied
- Search for `initialize()` without `initializer`, `onlyOwner`, or factory-based access control
- Trace all `burn()` call paths: does the burning contract verify both that the caller is approved AND is the intended depositor?

**False Positives**
- Function is intentionally permissionless (e.g., public liquidation that anyone should be able to trigger)
- Operation is harmless regardless of caller (e.g., anyone can trigger a public price update)
- Function only operates on `msg.sender`'s own data, making caller identity implicit

**Notable Historical Findings**
Isomorph's `withdrawFromGauge` burned the deposit NFT and sent the underlying AMM tokens to `msg.sender` without verifying that `msg.sender` owned the NFT; any approved operator could trigger the withdrawal and redirect the tokens to themselves rather than the legitimate depositor. Boot Finance's vesting function accepted any caller-supplied beneficiary address with no minimum amount, allowing an attacker to fill a victim's timelock array with thousands of dust entries until the legitimate claim function exceeded the block gas limit. Reserve Protocol's redemption function during undercollateralization could be hot-swapped by a searcher who front-ran the redemption transaction to substitute their own token for a more valuable basket asset.

**Remediation Notes**
- Add `require(depositReceipt.ownerOf(_NFTId) == msg.sender)` to all withdrawal functions before executing any transfer
- Restrict vesting to `msg.sender` as the beneficiary and enforce a minimum vest amount to prevent array-stuffing griefing
- Use `initializer` modifier or deploy-and-initialize atomically in a factory to close the initialization front-running window

---

### Missing Event Emissions After Sensitive Actions (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Administrative parameter changes (fee rates, scanner registration, whitelist modifications) execute silently without emitting events
- Off-chain monitoring systems and indexers rely on events to detect protocol state changes; missing events mean unauthorized changes may go undetected
- Fund distribution operations do not emit per-recipient events, making it impossible to audit payout history without replaying the full transaction calldata

**Detection Heuristics**
- Enumerate all external and public functions with `onlyOwner`, `onlyAdmin`, or similar modifiers; verify each emits an appropriate indexed event
- Focus on parameter change functions: fee rates, oracle addresses, access control roles, pause state
- Check upgrade and initialization functions for event emissions
- Verify that token transfers emit standard ERC-20/721 Transfer events from downstream calls, not just internal state changes

**False Positives**
- Function is a pure computation with no state changes
- Event is emitted by a downstream OpenZeppelin function (e.g., `_transfer` already emits `Transfer`)
- State change is trivially visible on-chain without event indexing (e.g., a storage slot update to a public variable)

**Notable Historical Findings**
Forta Protocol's scanner registration and configuration functions executed without event emissions, making it impossible for off-chain monitoring systems to detect unauthorized registrations or configuration changes without polling every storage slot. Notional's governance contracts updated critical parameters (voting thresholds, proposal weights) without events, creating a situation where governance attacks could modify protocol behavior with no observable on-chain trace beyond the raw transaction. Futureswap's admin functions similarly changed operational parameters without events, undermining the transparency guarantees that DeFi protocols rely on for user trust.

**Remediation Notes**
- Emit an indexed event for every admin-controlled parameter change, including the old and new values
- Define events for all role assignments and revocations with the granting address, receiving address, and role identifier
- For fund distributions, emit per-recipient events that allow reconstruction of the full payout history from event logs alone

---

### Missing Two-Step Ownership Transfer (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Privacy protocol uses `transferOwnership(newOwner)` that immediately replaces the owner with no confirmation step
- A typo in the new owner address or transfer to an uncontrolled contract permanently removes admin capability
- Diamond proxy patterns use a single-step `setContractOwner` without a pending/accept workflow

**Detection Heuristics**
- Search for `transferOwnership` functions that immediately assign the new owner without a `pendingOwner` pattern
- Confirm the contract inherits from `Ownable2Step` rather than `Ownable` for two-step transfer semantics
- Check for `renounceOwnership()` accessibility; this function permanently removes admin control
- Verify that all critical protocol contracts (treasury, governance, vault admin) use two-step transfer

**False Positives**
- Ownership is managed by a multisig that inherently provides confirmation before execution
- Contract is immutable and ownership is non-transferable by design
- Timelock provides a delay window sufficient for detecting and cancelling erroneous transfers

**Notable Historical Findings**
Beanstalk's diamond proxy used a single-step `transferOwnership` for the contract owner role, which controls the ability to add and remove diamond facets; a single erroneous transaction could have permanently locked the entire protocol's upgradeability. Boot Finance had no ownership transfer pattern at all-the owner address was immutable and the protocol had no path for governance succession. Reserve Protocol discovered that a `transferOwnership` flow without confirmation could leave the `StRSR` contract permanently unusable if ownership was transferred to a contract that could not call `acceptOwnership`.

**Remediation Notes**
- Use OpenZeppelin's `Ownable2Step` instead of `Ownable` for all protocol contracts with meaningful admin functions
- Override `renounceOwnership` to `revert` on contracts where admin functions must remain callable
- For diamond proxies, implement a `proposeOwner` / `acceptOwner` pattern at the `LibDiamond` level

---

### Operations Blocked During Pause or Freeze (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- `whenNotPaused` or `_checkIfCollateralIsActive` is applied equally to loan closure, collateral addition, and liquidation-blocking protective actions the same way it blocks new borrowing
- Interest or fee accrual continues during the paused period, penalizing users who cannot interact to protect their positions
- A single collateral's oracle going stale blocks all operations across the entire protocol, including full-repayment paths that do not require price information

**Detection Heuristics**
- Identify functions that should remain available during a pause (close loan, repay debt, add collateral) and verify they are not gated by the same pause modifier as new-loan functions
- Check if interest accrual (virtual price updates) continues when the protocol is paused; if so, positions degrade silently during the freeze
- Verify that full-repayment paths skip the collateral valuation check when the repayment amount covers all debt
- Look for parameter changes (fee rates, collateral factors) that can be applied during a pause without user ability to respond

**False Positives**
- Pause duration is extremely short by design and interest accrual during that window is negligible
- Emergency withdrawal function remains active during pause and provides an exit path
- Interest accrual is explicitly frozen during the pause period

**Notable Historical Findings**
Isomorph's `_checkIfCollateralIsActive` was called by all four core functions including `closeLoan` and `increaseCollateralAmount`, meaning a stale Lyra oracle price circuit-breaker permanently blocked every user action-including full repayments that required no price information-leaving borrowers unable to exit positions while interest continued to compound. Reserve Protocol's staking contract allowed new stake deposits during paused/frozen states, but withdrawals were blocked; this asymmetry allowed stake to enter but not exit, trapping new depositors. A separate Reserve finding showed that governance changes to `unstakingDelay` affected users who had already submitted withdrawal requests, retroactively extending their wait time.

**Remediation Notes**
- Remove the pause guard from `closeLoan`, `repayDebt`, and `increaseCollateralAmount`; these functions only improve position health and do not require price validation when the repayment covers all outstanding debt
- Freeze interest accrual atomically with the pause by updating `lastUpdateTime` to the pause timestamp and resetting it to `block.timestamp` on unpause
- Block parameter changes that worsen user positions (increased fees, reduced collateral factors) during a paused state

---

### Reentrancy via Token Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Privacy protocol's redeem function transfers multiple tokens in a loop before all internal state (total supply, basket state, nullifier commitments) is finalized
- ERC-777 tokens with `tokensReceived` hooks are accepted as shielded assets, enabling re-entry between the balance decrement and the nullifier registration
- Callback-based borrow, lend, or mint functions invoke `msg.sender` before updating note commitments or liquidity state

**Detection Heuristics**
- Identify all external token transfers in redemption and withdrawal loops; verify that all internal state is finalized before the loop begins, not after
- Check if `nonReentrant` is applied to all functions that invoke external callbacks (`ITimeswapMintCallback`, `onERC1155Received`, etc.)
- Verify that note commitments and nullifiers are registered before any external token transfer in deposit/withdrawal flows
- Search for ERC-777 token support; any `tokensReceived` hook can re-enter before state is committed

**False Positives**
- Protocol supports only well-known tokens (USDC, WETH) with no callback mechanisms, enforced by an allowlist
- Strict CEI is maintained throughout and all state is finalized before any external call
- `nonReentrant` covers all relevant entry points globally, not just individual functions

**Notable Historical Findings**
Reserve Protocol's `redeem` function transferred basket tokens to the user in a loop before finalizing `basketsNeeded` and other supply invariants, allowing an ERC-777 token recipient to re-enter `redeem` with stale supply state and extract more than their proportional share. Beanstalk's `FarmFacet` allowed re-entry during multi-step pipeline execution, enabling an attacker to drain intermediate value that accumulated during the pipeline handoff. Timeswap's `mint`, `lend`, `borrow`, and `pay` functions all invoked callbacks to `msg.sender` before completing their critical state updates (liquidity balances, fee accruals, debt positions), making every core function a reentrancy vector.

**Remediation Notes**
- Finalize all state updates (burn, supply reduction, nullifier/commitment updates) before beginning any external transfer loop
- Apply `nonReentrant` to every callback-invoking function (`mint`, `lend`, `borrow`, `redeem`, `pay`)
- For batch redemptions, split the function into a pure effects phase (update all internal state) and a pure interactions phase (execute all transfers)

---

### Rounding and Truncation Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Two different code paths compute the same aggregate collateral value using different aggregation orders (sum-then-price vs. price-each-then-sum), producing inconsistent results that can be exploited in comparison checks
- Virtual price (interest accumulator) updates use `block.timestamp` rather than truncating to the nearest interval boundary, permanently losing fractional time that should have been rolled forward
- Token precision multipliers computed as `10**(18 - decimals)` round to zero for tokens with more than 18 decimals, breaking pool math entirely

**Detection Heuristics**
- Find pairs of functions that compute the same logical value and verify they use identical aggregation order and rounding direction
- Search for `_updateVirtualPrice` or equivalent that stores `block.timestamp` after a truncated interval calculation; the stored time should be `truncatedIntervals * interval`, not `block.timestamp`
- Look for `customPrecisionMultipliers = 10**(18 - decimals)` without a guard against `decimals > 18`
- Identify all division operations where the result is later used in a comparison; ensure rounding direction is consistent between the two compared values

**False Positives**
- Truncation errors are within a documented dust threshold and cannot be amplified
- Protocol explicitly uses `mulDiv` for full-precision arithmetic throughout
- The aggregation-order difference is known and the comparison uses a dust-tolerance allowance to absorb the discrepancy

**Notable Historical Findings**
Isomorph's liquidation check compared `proposedAmount` (computed by pricing each NFT individually, truncating N times) against `totalCollateralValue` (computed by summing all NFTs then pricing once, truncating once), producing systematic differences that could prevent full liquidation even when the loan was deeply underwater. The same protocol's `_updateVirtualPrice` stored `_currentBlockTime` after computing interest for only truncated intervals, permanently discarding the fractional seconds remainder and under-accruing interest on every update cycle. Boot Finance's `customPrecisionMultipliers` calculation produced zero for any token with more than 18 decimals, causing division-by-zero or zero-value transfers that completely broke the pool for those token pairs.

**Remediation Notes**
- Standardize all collateral valuation paths to use the same aggregation order: sum all units first, then apply a single price conversion
- Store `(block.timestamp / interval) * interval` as the updated time, not `block.timestamp`, to ensure the accumulator advances in exact interval steps
- Guard precision multiplier calculations with `require(decimals <= 18, "Unsupported decimals")` or compute the inverse for tokens with more than 18 decimals

---

### Stale Oracle Data (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Oracle bounds (`tokenMinPrice`, `tokenMaxPrice`) are fetched from the Chainlink aggregator at deployment and stored as immutables; if Chainlink deploys a new aggregator with different bounds, the cached values become permanently stale
- Heartbeat staleness threshold is set to 24 hours for a feed that updates every 1 hour, allowing prices that are effectively stale to pass validation for 23 hours
- Oracle deprecation causes `latestRoundData()` or `refresh()` to revert unconditionally, permanently disabling the protocol path that depends on it

**Detection Heuristics**
- Search for `aggregator.minAnswer()` and `aggregator.maxAnswer()` stored in `immutable` variables in the constructor
- Verify staleness thresholds match the actual heartbeat for each specific Chainlink feed (not a single generic large value)
- Check `round completeness`: `answeredInRound >= roundID` must be verified in every `latestRoundData()` call
- Test oracle deprecation path: if the primary feed's `latestRoundData()` reverts, does the protocol halt permanently or fall back gracefully?

**False Positives**
- Oracle is used only for non-critical display purposes
- Protocol has admin-controlled manual price overrides that activate during oracle failures
- Staleness window is generous but acceptable within the protocol's epoch duration

**Notable Historical Findings**
Isomorph's oracle bounds were cached at construction time; when Chainlink deprecated an aggregator and deployed a replacement with updated min/max bounds, the cached bounds no longer matched the live feed-causing the protocol to either reject valid prices or accept invalid ones indefinitely. Reserve Protocol's `refresh()` function propagated an oracle deprecation exception upward without catching it, disabling the entire basket recollateralization path the first time any oracle in the basket was deprecated. A separate Reserve finding showed that `Asset.lotPrice()` did not fall back to a safe low price on oracle timeout, instead using a potentially stale cached price for asset sales, enabling significant underpayment to the protocol.

**Remediation Notes**
- Fetch aggregator bounds dynamically (`priceFeed.aggregator().minAnswer()`) on every oracle query rather than caching them at construction
- Set heartbeat thresholds per-feed based on documented update frequencies, not a single global constant
- Wrap all oracle calls in `try/catch` and route failures to a fallback price source or a safe degraded mode that halts new operations while allowing existing position closures

---

### Stuck or Permanently Locked Funds (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- The only withdrawal path calls `priceCollateralToUSD` which reverts when the oracle price falls outside its min/max bounds, permanently locking all collateral for affected users
- A failed prior proposal in an NFT fractionalization or escrow contract leaves the contract in a state where no new proposal can be executed and funds cannot be recovered
- A single collateral type whose oracle becomes permanently unavailable prevents `rebalance()` from executing, blocking the entire basket

**Detection Heuristics**
- Trace all withdrawal and redemption paths and verify at least one path remains functional when external dependencies (oracle, external protocol) revert
- Check if oracle out-of-bounds conditions block full-repayment paths where collateral pricing is not economically necessary
- Search for contracts that receive tokens with no `rescueTokens` or `sweep` function for accidentally deposited assets
- Verify that a single failing basket component is handled gracefully (try/catch continuation) rather than blocking all basket operations

**False Positives**
- Admin emergency withdrawal function exists and bypasses normal checks
- Stuck condition is temporary and self-resolving (oracle will update within the heartbeat window)
- Governance mechanism can migrate or rescue stuck funds within a bounded time frame

**Notable Historical Findings**
Isomorph's `closeLoan` always called `_calculateProposedReturnedCapital` even when the user was repaying their entire debt and no collateral pricing was needed; when the oracle price moved outside bounds, this single check permanently locked all collateral for every user of the affected collateral type. Tessera's `OptimisticListingSeaport` could enter a permanently stuck state if a new proposal was created while an active proposal was being executed, leaving both proposals irreconcilable and all fractionalized NFT proceeds inaccessible. Reserve Protocol identified that if a single collateral asset in the basket behaved unexpectedly (oracle revert, non-standard behavior), the entire `RToken` would become permanently insolvent and unusable.

**Remediation Notes**
- For full-repayment closure paths, skip collateral valuation when `outstandingDebt == 0`; allow withdrawal of all collateral without any price check
- Add a `rescueTokens(IERC20 token, address to)` function that excludes the protocol's primary tokens and can recover accidentally deposited assets
- In basket rebalance loops, use `try/catch` around individual collateral price queries and emit a failure event for the affected asset rather than reverting the entire operation
