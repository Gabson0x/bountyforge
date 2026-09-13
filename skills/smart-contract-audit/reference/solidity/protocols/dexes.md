# DEX and AMM Security Patterns

> Applies to: AMM, DEX, swap protocols, Uniswap-style, Curve-style, Balancer-style, order books, concentrated liquidity, token swap, liquidity managers, position managers, Arrakis-style, Gamma-style, concentrated liquidity position management, Uniswap v3 position wrappers

## Protocol Context

DEX and AMM protocols are architecturally defined by constant-product or curve-based invariant math, real-time liquidity pool mechanics, and dense external call flows involving token callbacks, oracle reads, and router integrations. Their pricing state is determined entirely by on-chain reserves or slot data, making it trivially manipulable within a single transaction by anyone holding sufficient capital or flash loan access. MEV exposure is structural: every state-changing operation that involves a price-sensitive output visible in the public mempool is a candidate for sandwich attack, front-running, or oracle manipulation.

## Bug Classes

---

### Front-Running and MEV (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Swap or trade functions compute `amountOutMinimum` on-chain from current pool reserves or a quoter call, which the attacker has already moved
- Deadline is set to `block.timestamp`, providing no execution-time protection
- Automated keeper or harvest flows call swaps without user-supplied slippage bounds
- Permit signatures are submitted in the same transaction as the main call, enabling front-run DoS by replaying the permit first
- Rebalance operations in concentrated liquidity managers compute `sqrtPriceLimitX96` from `slot0().sqrtPriceX96`, which is movable by a flash loan executed in the same block as the rebalance transaction
- Position manager `rebalance()` and `init()` functions pass `amount0Min: 0` and `amount1Min: 0` to `NonfungiblePositionManager.mint()` and `increaseLiquidity()` without accepting caller-supplied bounds
- Deposit routing across multiple Uniswap V3 fee tiers does not enforce a minimum pool liquidity check, allowing a front-runner to thin the target pool before the deposit is routed

**Detection Heuristics**
- Search for swap calls where `amountOutMinimum`, `amountOutMin`, or `minAmountsOut` is set to `0` or computed in the same transaction from `quoter.quoteExactInput()` or `getReserves()`
- Check for `deadline: block.timestamp` in `ExactInputSingleParams` or equivalent swap structs
- Identify automated compound/harvest functions that route reward tokens through a DEX with no user-controlled minimum
- Check for `IERC20Permit.permit()` calls not wrapped in `try/catch`
- In concentrated liquidity managers, check all `NonfungiblePositionManager.mint()`, `increaseLiquidity()`, and `decreaseLiquidity()` call sites for `amount0Min: 0` and `amount1Min: 0`
- Verify that `rebalance()` and `init()` functions in position manager contracts accept explicit `slippage` and `deadline` parameters rather than deriving them from on-chain pool state

**False Positives**
- The function is only callable by a trusted keeper using a private mempool relay (Flashbots, MEV Blocker)
- Slippage bounds are enforced at a higher layer, such as an aggregator router that validates output before forwarding
- The swap amount is dust-level in a pool with deep liquidity, making sandwich attacks economically irrational

**Notable Historical Findings**
Multiple DEX integrations at protocols including Derby and Blueberry contained swap calls in vault harvest and reward-compounding functions where `amountOutMinimum` was hardcoded to zero, exposing the full swap value to sandwich attacks. Redacted Cartel's AutoPxGmx compound function allowed anyone to trigger a swap with caller-controlled slippage parameters, enabling a third party to set zero-minimum swaps and profit from the resulting sandwich. Cron Finance identified overpayment of one LP pair side during `joinPool` due to no slippage guard, directly extractable via MEV. Notional's settlement slippage was either bypassable or implemented incorrectly across multiple findings, making vault settlement vulnerable to predatory execution ordering.

**Remediation Notes**
Accept `minAmountOut` and `deadline` as explicit caller parameters in all functions that execute swaps, including automated flows. For keeper-executed paths, derive the minimum from an oracle price with a configurable `MAX_SLIPPAGE_BPS` tolerance rather than from on-chain pool state. Wrap all `permit()` calls in `try/catch` so a replayed permit does not brick the main transaction.

---

### Liquidation Logic Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Liquidation functions share a pause state with deposit or repay operations, so pausing one disables the other
- Position health factor reads `totalAssets()` or share price without first accruing interest, understating or overstating actual collateral value
- An origination fee is applied at loan creation time but the health check runs before the fee is deducted, producing a position that is immediately liquidatable
- The liquidation path iterates over dynamic collateral type arrays that can grow to exceed the block gas limit

**Detection Heuristics**
- Check if liquidation functions contain a generic `require(!paused)` that also blocks them when unrelated modules are paused
- Verify that `_accrueInterest()` or equivalent is called before any health factor read in the liquidation path
- Look for `origination_fee` applied after the collateral check that would push a new position below the liquidation threshold
- Check if Balancer BPT or other LP token valuations used for collateral rely on `getReserves()` or `slot0()` rather than TWAP

**False Positives**
- The protocol intentionally disables liquidations during an oracle failure mode with an explicit `oracleDown` flag distinct from the general pause
- Health factor checks always use the more conservative of cached versus live price

**Notable Historical Findings**
Blueberry had a finding where repayments being disabled via one flag would cause borrowers to lose collateral without the ability to repay, while liquidations remained enabled. Morpho exhibited state desynchronization where liquidating a user's position through Aave would leave Morpho's internal accounting diverged from the actual Aave position, creating exploitable inconsistencies. Astaria contained numerous liquidation path flaws including incorrect auction end validation, improper handling of winning versus non-winning bids on Seaport, and lien stack updates that did not propagate correctly on partial payments. Sentiment found that the origination fee could make a freshly opened position immediately liquidatable at loan inception.

**Remediation Notes**
Liquidation must have its own pause flag, independent of deposit or repay pauses. Always trigger interest accrual before any health factor or collateral valuation read. Validate that no combination of fee application and collateral check ordering can produce a liquidatable position immediately after opening.

---

### Oracle Price Manipulation (ref: fv-sol-10, fv-sol-10-c5, fv-sol-10-c6, fv-sol-10-c7)

**Protocol-Specific Preconditions**
- Protocol reads `IUniswapV3Pool.slot0()` for pricing; slot0 reflects the last executed trade and is trivially movable by a flash loan in the same transaction
- Chainlink `latestRoundData()` is called without checking `updatedAt` staleness, `answeredInRound >= roundId` completeness, or minAnswer/maxAnswer circuit breaker bounds
- The protocol uses an LP token oracle (e.g., IchiVault) that derives price from internal token balances, which are directly influenced by single-sided deposits
- No fallback oracle exists when the primary feed returns zero or reverts
- Concentrated liquidity managers read `slot0().sqrtPriceX96` to compute `sqrtPriceLimitX96` passed to the pool during a rebalance swap, making the swap limit directly manipulable in the same block
- Rebalance trigger logic reads `slot0().tick` to determine whether the current price has moved outside the managed tick range; an attacker can temporarily move the tick to force or prevent a rebalance

**Detection Heuristics**
- Search for `slot0()` calls used directly in price or valuation calculations without a corresponding `observe()` TWAP call
- Check every `latestRoundData()` call: confirm `updatedAt > 0`, `block.timestamp - updatedAt <= MAX_STALENESS`, `answeredInRound >= roundId`, `answer > 0`
- Verify that the returned `answer` is checked against `minAnswer` and `maxAnswer` from the underlying aggregator (circuit breaker scenario)
- Search for `getReserves()` in Uniswap V2 or `IUniswapV2Pair.getReserves()` used for pricing without TWAP
- Check any path that passes `slot0().sqrtPriceX96` or `slot0().tick` directly into `NonfungiblePositionManager` or pool swap parameters in a manager contract
- Verify that rebalance trigger conditions use `IUniswapV3Pool.observe()` TWAP ticks rather than `slot0().tick` for determining whether a position is out of range

**False Positives**
- TWAP window is sufficiently long (30+ minutes) and the pool has liquidity deep enough to make manipulation cost-prohibitive
- A secondary oracle provides a sanity-check bound that catches manipulation before it reaches critical state
- Staleness threshold is deliberately tuned to the specific Chainlink feed's heartbeat interval (some feeds update every 24 hours)

**Notable Historical Findings**
Blueberry contained three separate oracle findings: ChainlinkAdapterOracle returned stale prices due to missing freshness checks, the WBTC feed used BTC/USD without accounting for potential WBTC depeg, and the IchiLpOracle derived prices from IchiVault internal balances that were easily manipulated via single-sided deposits. Float Capital's entire market misbehaved when a Chainlink feed had an update gap, because no staleness validation existed. Notional relied on a Balancer oracle that updated infrequently, making its collateral valuations exploitably stale during low-activity windows. ParaSpace incorrectly valued UniswapV3 LP positions by mishandling tokens of different decimal scales in the price formula, leading to wrongly triggered liquidations.

**Remediation Notes**
Never use `slot0()` for pricing in critical protocol paths; use `observe()` with a TWAP interval of at least 30 minutes. For Chainlink, validate all five return values from `latestRoundData()` and check circuit breaker bounds. For LP token oracles, derive price from external reference prices rather than internal balance ratios.

---

### Access Control (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- State-changing functions that modify fee parameters, reward token lists, pool configuration, or upgrade paths are exposed as `external` without ownership or role guards
- Approval and token transfer functions in LP/order-book implementations omit `msg.sender` authorization checks against the `from` address
- Diamond proxy facets have globally accessible state variables rather than namespaced storage, allowing one facet to corrupt another's state
- Admin roles have unrestricted power over fee collection, token transfers, and allowance changes with no timelock
- `rebalance()`, `reinvest()`, and `compound()` functions in concentrated liquidity manager contracts are externally callable without a keeper or governance guard, allowing any caller to trigger rebalance at a strategically unfavorable time
- Fee collection calls that forward collected tokens to a caller-supplied `recipient` parameter do not validate the recipient against a stored `feeRecipient`, allowing an unauthorized caller to redirect fees

**Detection Heuristics**
- Scan all `external` and `public` state-mutating functions for the absence of `onlyOwner`, `onlyRole`, or equivalent modifiers
- Check `transferFrom` implementations for the three-way authorization: `msg.sender == from || isApprovedForAll(from, msg.sender) || getApproved(id) == msg.sender`
- In diamond proxy contracts, look for global variable declarations that should use `getStorage()` or a namespace pattern
- Identify functions that can be called through a proxy fallback that bypasses the checks on the implementation
- Check if `rebalance()`, `reinvest()`, or `compound()` in position manager contracts have `onlyManager`, `onlyOwner`, or `onlyStrategist` guards
- For functions that call `NonfungiblePositionManager.collect()` with a caller-supplied recipient, verify the recipient is constrained to a pre-registered `feeRecipient` address

**False Positives**
- The function is intentionally permissionless because it is a view or performs a beneficial public action such as liquidation or fee distribution
- Access control is enforced upstream in the router or wrapper that is the sole entry point

**Notable Historical Findings**
CLOBER had a missing ownership check in its token transfer path, allowing any caller to invoke `transferFrom` on behalf of any holder. Astaria contained a case where anyone could take a loan on behalf of any collateral holder without authorization, using valid commitment data from a self-registered vault. Connext exposed `acceptanceDelay` mutation to arbitrary callers, allowing unauthorized modification of a security-critical timing parameter. LI.FI's GenericBridgeFacet allowed arbitrary external calls with approved token balances because call targets were not whitelisted, effectively granting any caller the ability to route approved tokens to an attacker address.

**Remediation Notes**
Apply `onlyOwner` or role-based guards to all functions modifying protocol configuration. In diamond proxies, enforce namespaced storage via EIP-2535 best practices to prevent cross-facet state pollution. Wrap sensitive admin operations in timelocks and multisig requirements.

---

### Stale State After Actions (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Transfer or buyout of a lien, position, or LP token does not update the associated payee, slope, or intercept mappings
- Interest accrual is not triggered before adding a new loan or reading total debt, causing overborrowing against understated debt
- Order NFT burns leave ownership or order data mappings non-zeroed, enabling token ID recycling attacks
- Diamond storage gaps (`__gap`) are not correctly sized, risking storage slot collision on upgrade

**Detection Heuristics**
- After any ownership transfer path, verify that payee, approval, and claim mappings are all updated atomically
- Search for loan or position creation functions that add to `totalDebt` without first calling `_accrueInterest()`
- Look for `_burn()` calls not followed by explicit `delete ownerOf[tokenId]` and associated data cleanup
- Check if `stateHash` is updated in all code paths that modify lien state, not just the primary path

**False Positives**
- The protocol uses a lazy accrual pattern where any subsequent interaction with the position forces a state catch-up, and this is consistently enforced across all entry points
- The stale value is overwritten atomically in the same transaction before it can be read by any dependent calculation

**Notable Historical Findings**
Astaria contained more than ten findings related to stale state, including `makePayment` not properly updating the lien stack, `setPayee` not updating the y-intercept or slope (allowing vault owners to redirect funds), `stateHash` not being updated on `buyoutLien`, and clearing house state not reflecting auction outcomes when a Seaport bid was non-winning. CLOBER had order ownership not zeroed after burning, which combined with predictable token ID recycling allowed theft of future order NFTs. Morpho Aave position liquidation left internal Morpho state desynced from the actual Aave state after a cross-protocol liquidation call.

**Remediation Notes**
Treat state updates as atomic sets: any operation that changes ownership, debt, or accounting must update every derived or associated mapping in the same call. Enforce interest accrual as the first action in any path that reads total debt or share price.

---

### Reentrancy (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Pool reserve or `totalAssets` state is updated after token transfers, creating a window where an ERC-777 or hook-bearing token callback can read stale reserves
- Read-only reentrancy: `getReserves()` or `slot0()` is consumed by an external pump or oracle contract mid-transfer, before the pool finalizes its state update
- ERC-721 `safeTransfer` or `safeTransferFrom` triggers `onERC721Received` on a malicious receiver that reenters the DEX
- The `nonReentrant` guard is applied to one entry point but not to all functions sharing the same state
- `NonfungiblePositionManager.collect()` is invoked to realize accrued fees before the manager's internal fee accounting is updated, allowing a re-entrant call during the token transfer callback to observe stale unclaimed fee balances
- Position NFT transfers trigger `onERC721Received` on the recipient before the prior owner's position record is cleared, enabling the recipient to call back into the manager against a half-updated ownership state

**Detection Heuristics**
- Check if `_setReserves()` or equivalent pool state finalization happens before or after token transfers to recipients
- Look for Balancer read-only reentrancy: any protocol reading Balancer pool reserves via `getPoolTokens()` without confirming the pool is not mid-execution
- Identify ERC-777 tokens in scope; any `safeTransfer` to a user-controlled address with state not yet committed is a reentrancy vector
- Verify that every function sharing mutable state with a `nonReentrant` function is also guarded
- Check whether `NonfungiblePositionManager.collect()` calls in manager contracts precede any state variable updates that track unclaimed fees or position balances
- Look for `safeTransferFrom` of position NFTs where `onERC721Received` fires before the sender's position mapping is zeroed

**False Positives**
- The external call targets WETH or another immutable contract with no callback path
- All state is committed (effects applied) before any interaction, with strict CEI compliance verified end-to-end
- The contract only accepts tokens from a hardcoded whitelist that excludes ERC-777 and hook-bearing tokens

**Notable Historical Findings**
Beanstalk Wells had a read-only reentrancy finding where pumps (oracle-like components) were updated using pool reserves that had not yet been finalized after a liquidity removal, allowing external callers to read stale state via callbacks during the transfer phase. CLOBER's `collectFees` function drained tokens due to reentrancy because fee state was updated after the token transfer. Caviar's buy function allowed a discount-priced purchase using ERC-777 tokens by reentering before the price state was updated. Notional Finance's `redeemNative()` reentrancy enabled permanent fund freeze and systemic misaccounting by allowing reentrant calls to execute against uncommitted liquidation state.

**Remediation Notes**
For AMMs, update reserves and burn LP tokens before transferring tokens to users. Apply `nonReentrant` to all entry points sharing pool state, not just the swap path. For read-only reentrancy, downstream oracle consumers of Balancer or other multi-token pool reserves must check that the pool is not currently in an execution context before reading.

---

### Integer Overflow and Underflow (ref: fv-sol-3)

**Protocol-Specific Preconditions**
- `unchecked` blocks are used in LP points tracking or reward accumulation where subtraction can underflow if a position is modified concurrently or out of order
- UniswapV3 swap return values (`int256 amount0`, `int256 amount1`) are cast to `uint256` without negating the sign convention, causing the caller to treat a debit as a credit
- Type-narrowing casts (`uint256` to `uint128`, `int256` to `int128`) in pool accounting occur without a bounds check
- Solidity < 0.8.0 is used in any component, or `unchecked` is applied to multiplication of user-controlled values

**Detection Heuristics**
- Search for `unchecked { ... }` containing subtraction, particularly in reward point or LP accounting
- Search for `uint256(-amount1)` or the absence of negation when consuming `IUniswapV3Pool.swap()` return values
- Look for `int256(uint256Value)` casts without a preceding `require(value <= uint256(type(int256).max))`
- Check for `uint128(uint256Value)` or `uint64(uint256Value)` without explicit bounds checks in tick or fee accumulator math

**False Positives**
- The `unchecked` block is in a context where prior guards mathematically guarantee no overflow or underflow
- The narrowing cast is immediately preceded by an explicit `require(value <= type(uintN).max)` check

**Notable Historical Findings**
Neo Tokyo's LP withdrawal function contained an `unchecked` subtraction on `lpPosition.points` that could underflow, granting the caller near-infinite points and enabling unlimited reward claims. Maia DAO's `RootBridgeAgent` was vulnerable to DoS because UniswapV3 `swap()` return values were not negated before being cast to unsigned types, causing the agent to misinterpret token debts as credits. Cron Finance's long-term swap implementation lost proceeds in pools with decimal or price imbalances because accumulator types were too narrow for the values produced. Astaria's `claim()` reverted for any token without 18 decimals due to an unchecked underflow in the amount calculation.

---

### Missing Slippage Protection (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- The swap's `amountOutMinimum` is zero or computed on-chain from pool state (quoter), which is already manipulable by the time the transaction executes
- Balancer `joinPool` or `exitPool` calls have `minAmountsOut` arrays set to all zeros
- Deadline is absent or set to `block.timestamp` (always passes regardless of block inclusion delay)
- Automated flows (compound, harvest, rebalance) execute swaps triggered by any caller with no minimum output parameter
- Concentrated liquidity manager `init()` and `rebalanceAll()` pass `amount0Min: 0` and `amount1Min: 0` to `NonfungiblePositionManager.mint()`, `increaseLiquidity()`, and `decreaseLiquidity()` without accepting user-supplied bounds
- Position manager deposit functions that route across multiple Uniswap V3 fee tiers select a pool at transaction time without enforcing a minimum liquidity threshold, allowing front-runners to thin the target pool first

**Detection Heuristics**
- Search for `amountOutMinimum: 0` or `minAmountsOut` filled with zeros in DEX swap call structs
- Check if swap minimum is computed by calling `quoter.quoteExactInput()` or reading `getReserves()` within the same transaction as the swap
- Look for `deadline: block.timestamp` which is always satisfied and provides no staleness protection
- Identify functions callable by any address that internally execute swaps without accepting a `minOut` parameter
- Check all `NonfungiblePositionManager.increaseLiquidity()` and `decreaseLiquidity()` struct parameters in manager contracts for `amount0Min` and `amount1Min` hardcoded to zero
- Verify that `init()` and `rebalance()` entry points in Arrakis-style or Talos-style manager contracts expose `slippage` and `deadline` as explicit caller parameters

**False Positives**
- Swap minimum is derived from a time-lagged oracle price with a tight deviation threshold, providing equivalent or stronger protection than a user-specified value
- The function is only accessible to a privileged keeper that routes through a private mempool
- The pool is a stableswap with essentially no price impact for the swap size in question

**Notable Historical Findings**
Derby's vault swap functions across two separate findings both executed swaps with `amountOutMinimum` hardcoded to zero, making every vault harvest fully sandwichable. Blueberry's IchiVaultSpell withdrawals lacked slippage protection, allowing front-runners to steal a portion of the withdrawn ICHI rewards. Notional's vault settlement slippage was either bypassable or computed incorrectly in multiple findings, with one path allowing the calculated slippage bound to always be exceeded. Redacted Cartel's AutoPxGmx `compound()` was callable by anyone with caller-controlled slippage parameters, directly enabling sandwich attacks on the compound operation.

**Remediation Notes**
Require callers to supply `minAmountOut` and `deadline` parameters for all DEX-interacting functions. For automated keeper flows, compute the floor from an oracle price with a bounded tolerance rather than from pool state.

---

### Incorrect Math Calculations (ref: fv-sol-3)

**Protocol-Specific Preconditions**
- Interest rate or fee divisor uses a hardcoded constant with the wrong decimal scale (e.g., `1e17` where `1e18` is needed)
- Fee deduction is applied to the total position size rather than only the incremental delta being added
- AMM pool invariant or custom pricing formula deviates from the specification due to operator precedence or wrong variable substitution
- Velodrome-style forks use hardcoded Uniswap V2 fee values (0.3%) in `getAmountIn` rather than reading the pool's custom fee

**Detection Heuristics**
- Cross-reference all divisors and multipliers in financial formulas against the intended decimal precision
- Check fee calculations: the fee base should be `newAmount`, not `existingAmount + newAmount`, unless the specification explicitly states otherwise
- For Uniswap V2 forks with custom fees, check whether `getAmountIn` / `getAmountOut` use hardcoded `997/1000` instead of the pool's dynamic fee
- Verify reward distribution formulas against the protocol specification or whitepaper

**False Positives**
- The apparent wrong constant is a deliberate approximation whose bounded error is documented and economically immaterial
- The formula is a simplified equivalent of the specification with provably equivalent output

**Notable Historical Findings**
Astaria's strategist interest rewards were calculated with a divisor of `1e17` instead of `1e18`, producing interest ten times higher than intended. Velodrome Finance's `UniswapV2Library.getAmountIn` used hardcoded 0.3% fees from the original Uniswap V2 code despite Velodrome pools having configurable custom fees, causing incorrect quoted amounts. Tigris Trade had an incorrect new price calculation when adding to a position, because the price update formula used the wrong variable as the price base. Rage Trade's `DnGmxJuniorVaultManager._totalAssets` didn't correctly optimize or minimize in certain rebalance states due to a wrong price calculation path.

---

### Rounding and Precision Loss (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Reward share calculations perform division before multiplication: `(userShare / totalShares) * totalReward` truncates to zero when `userShare < totalShares`
- Deposit share minting uses `assets * totalSupply / totalAssets` where `totalAssets` can be inflated by a direct token donation, causing victim deposits to mint zero shares
- Taker fee rounding up across constituent order components produces a total fee that exceeds the collected amount
- Long-term swap accumulator values lose precision in pools where token decimals differ significantly (e.g., 8-decimal vs. 18-decimal)
- Fee growth calculations inside tick ranges use `uint256` arithmetic that wraps by design under the Uniswap V3 spec; applying Solidity 0.8 checked arithmetic to `feeGrowthInside` deltas causes spurious reverts
- `tickCumulatives` calculations in position range validation use a hardcoded fee tier constant instead of reading `IUniswapV3Pool.fee()`, producing incorrect TWAP values for non-standard fee tiers (500, 3000, 10000 bp pools)

**Detection Heuristics**
- Look for division operations followed by multiplication in the same expression; reverse the order
- Check share minting formulas for the case where `totalAssets` has been inflated by a direct transfer: can the result round to zero for a normal deposit amount?
- Verify rounding direction: deposits and mints should round shares DOWN (fewer shares minted), withdrawals and redeems should round assets UP (more assets required)
- Check `mulDiv` usages for correct rounding mode (`ROUND_DOWN` vs. `ROUND_UP`) relative to the operation's direction
- Verify that `feeGrowthInside0LastX128` and `feeGrowthInside1LastX128` subtraction in fee collection math is wrapped in `unchecked` blocks, matching Uniswap V3's overflow-by-design semantics
- Search for hardcoded fee tier values (`500`, `3000`, `10000`) used in `observe()` calls or fee growth arithmetic where `pool.fee()` should be read dynamically instead

**False Positives**
- Precision loss is bounded to 1-2 wei per operation and has no compounding effect
- The protocol uses a fixed-point math library (PRBMath, FixedPoint96) that handles rounding correctly by design

**Notable Historical Findings**
Caviar's first depositor could break share minting by depositing 1 wei, then donating a large token amount directly to the vault, causing subsequent depositors to receive zero shares for non-trivial deposit amounts. Astaria's first vault deposit caused excessive rounding that allowed the first depositor to extract value from subsequent depositors. CLOBER's taker fee rounding up across constituent orders could produce a total fee exceeding the collected amount, causing an invariant violation. Alchemix's misuse of Curve pool return values produced both precision loss and unintended reversions due to incorrect handling of the pool's output scaling.

---

### Flash Loan Attacks (ref: fv-sol-8-c1, fv-sol-10-c3)

**Protocol-Specific Preconditions**
- Reward eligibility or governance voting power is based on instantaneous balance rather than a time-weighted or checkpointed snapshot
- Staking functions have no minimum lock duration, allowing stake-claim-unstake in a single transaction
- BPT or LP token balance thresholds are checked at call time rather than at a prior block snapshot
- Liquidity pool share price or exchange rate can be temporarily moved by a large single-block deposit or withdrawal

**Detection Heuristics**
- Check if reward calculations read `stakedBalance[msg.sender]` or `balanceOf(msg.sender)` without verifying a minimum stake duration has elapsed
- Look for governance threshold checks on live token balances: `require(token.balanceOf(msg.sender) >= THRESHOLD)` without using `getPriorBalance()` or equivalent
- Verify that `exchangeRateStored()` or share price values used for collateral or reward calculations are not updatable within the same block by large deposits
- Identify flash loan callback entry points that allow arbitrary operations before repayment

**False Positives**
- The protocol uses `getPriorVotes()` or block-snapshot checkpoints that are immune to same-block manipulation
- Reward calculations use time-weighted balances accumulated over multiple blocks

**Notable Historical Findings**
Telcoin allowed flash loan of TEL tokens to stake and exit within a single block, enabling an attacker to claim rewards proportional to the entire flash-loaned amount without having staked for any meaningful duration. Notional's Balancer vault integration was vulnerable to an attacker bypassing BPT thresholds by flash-loaning the required BPT balance, satisfying the threshold check, and then returning the BPT before the block ended. Carapace had a sybil/flash loan vector on withdrawal requests that allowed leveraged manipulation of a vault's leverage factor by coordinating multiple flash-borrowed withdrawal requests. Union Finance's `exchangeRateStored()` could be front-run immediately after a repayment to extract the rate change before the on-chain state settled.

---

### Griefing and Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Public functions iterate over arrays that grow unboundedly with user interaction (deposit lists, order queues, reward token arrays)
- A single failing token transfer in a batch distribution reverts the entire transaction
- Protocol operations have a gas budget that can be exhausted by an attacker creating dust positions at low cost
- Pool interest rate parameters can be manipulated by an attacker to make borrowing economically unviable for honest users
- Liquidity managers that support multiple tick ranges iterate over all managed positions in a single `rebalanceAll()` call; cheap dust positions added by an attacker can inflate the array to exceed the block gas limit

**Detection Heuristics**
- Look for `for` loops iterating over `deposits.length`, `positions.length`, or similar user-influenced arrays without a maximum iteration bound
- Check batch token distribution functions for `transfer()` calls without `try/catch`; a single reverting token locks all distributions
- Check Ajna-style interest rate manipulation: can an attacker add and remove liquidity at extreme rate bands to push rates above market?
- Search for `permit()` calls without `try/catch` that revert the entire function when the permit is front-run
- Check if `rebalanceAll()` or equivalent multi-range iteration functions have a maximum batch size or pagination mechanism

**False Positives**
- Arrays have an enforced maximum length that is small enough to safely iterate within block gas limits
- The griefing attack costs more in gas than the damage inflicted on the victim
- Batch operations emit failure events per item rather than reverting on partial failure

**Notable Historical Findings**
Ajna's interest rate mechanism could be raised above market levels as a griefing attack by repeatedly manipulating rate bands, disabling the pool for legitimate borrowers at low attacker cost. Biconomy's `handleOps` and `multiSend` logic was vulnerable to griefing via failing operations in a batch that caused the entire multi-operation to revert. Stakehouse Protocol's giant pool ETH bringback function allowed any caller to cause pool DOS by exploiting the idle ETH accounting, orphaning other users' LP positions. Predy's `_removePosition` could be permanently DoS'd by a specific sequence of position interactions, locking the user's position in the protocol.

---

### Token Decimal Mismatch (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Protocol assumes all tokens have 18 decimals but accepts USDC (6), USDT (6), or WBTC (8)
- Oracle price (returned in 18 decimals) is multiplied directly by a raw token amount without normalizing the token amount to 18 decimals first
- Cross-pool or cross-token calculations (collateral vs. debt in different tokens) mix raw amounts from tokens of different decimal scales
- UniswapV3 position valuations combine `token0` and `token1` amounts without accounting for their individual decimal scales

**Detection Heuristics**
- Search for hardcoded `1e18` or `10**18` in token amount formulas; verify the token's actual decimal count
- Check if `IERC20Metadata(token).decimals()` is called and used to normalize before financial calculations
- Look for `claim()` or `redeem()` paths that would underflow or return dust for 6-decimal tokens
- Verify that collateral valuation formulas correctly scale between oracle decimals (typically 8 for Chainlink) and token decimals

**False Positives**
- The protocol's token whitelist exclusively allows 18-decimal tokens, enforced at admission time
- Decimal normalization is applied in an oracle adapter layer so all prices reaching the core protocol are already normalized

**Notable Historical Findings**
Blueberry's IchiVaultSpell transferred too few ICHI v2 reward tokens to users because the decimal precision of ICHI v2 differed from the hardcoded assumption. Taurus assumed 18 decimals for collateral throughout its core logic, causing catastrophic mispricing for any non-18 decimal collateral. Astaria's `claim()` function underflowed and reverted for tokens with fewer than 18 decimals because the amount calculation assumed 18-decimal scaling. ParaSpace wrongly valued UniswapV3 positions when the underlying token pair contained tokens of different decimal scales, leading to incorrectly triggered liquidations.

---

### First Depositor and Vault Share Inflation (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Vault has no virtual shares or virtual asset offset, and no minimum initial deposit requirement
- `totalAssets()` includes the vault's own token balance, making it susceptible to inflation via direct token donation
- First depositor receives shares at exactly 1:1 before any pooled state exists, then can inflate `totalAssets` to make subsequent share minting round to zero
- The vault is ERC-4626 compatible but does not implement the OpenZeppelin virtual offset pattern

**Detection Heuristics**
- Check if `totalSupply() == 0` receives special handling; if not, check if the standard formula `assets * totalSupply / totalAssets` can produce zero shares for a reasonable first deposit
- Verify that `totalAssets()` does not include direct token balance of the vault contract (i.e., is immune to donation)
- Look for absence of `_decimalsOffset()` override in ERC-4626 implementations
- Check if dead shares are minted to `address(0xdead)` or a similar sink at first deposit

**False Positives**
- The vault uses OpenZeppelin ERC-4626 with a non-zero `_decimalsOffset()`, which introduces virtual shares
- A minimum first deposit amount makes the inflation attack economically infeasible
- Internal accounting uses a separate accumulator that is not influenced by direct token transfers

**Notable Historical Findings**
Caviar's first depositor could break share minting for all subsequent depositors by performing a 1 wei seed deposit followed by a large direct token transfer. Redacted Cartel's AutoPxGmx and AutoPxGlp vaults were vulnerable to share price manipulation via this pattern, allowing an attacker to drain depositor assets. Mycelium had an explicit finding where an attacker could manipulate `pricePerShare` to profit from future deposits. Maverick's `getOrCreatePoolAndAddLiquidity` in the router could be front-run to create the pool with a manipulated initial price, distorting the first liquidity provider's position.

---

### ERC-4626 Vault Compliance (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- `maxWithdraw()` or `maxRedeem()` return the total asset balance without accounting for time-locked funds, withdrawal queues, or epoch-based restrictions
- `previewDeposit()` and `previewRedeem()` do not account for protocol fees, causing integrators to receive fewer shares or assets than previewed
- The vault's ERC-4626 router calls `vault.deposit()` but the router has not approved the vault to pull its tokens, causing permanent reversion
- USDT-style tokens require resetting allowance to zero before setting a new non-zero value, breaking router approve flows
- `totalAssets()` does not include uncollected Uniswap V3 position fees (`tokensOwed0`, `tokensOwed1`), causing share price to be understated until `collect()` is explicitly called and creating sandwich opportunities around fee collection events
- A vault wrapping a concentrated liquidity position has a `convertToAssets()` value that changes with every swap in the underlying pool; share issuance is not idempotent within a block

**Detection Heuristics**
- Verify that `maxWithdraw(owner)` reflects only the liquid, immediately withdrawable portion, not the total claimed balance
- Check `previewDeposit` and `previewWithdraw` implementations for fee inclusion and correct rounding direction
- Look for router patterns where `asset.approve(vault, amount)` is called without first pulling the tokens to the router
- Check for `safeApprove` usage with USDT where a non-zero-to-non-zero approval revert would lock the router
- Check whether `totalAssets()` reads `tokensOwed0` and `tokensOwed1` from the NonfungiblePositionManager or explicitly calls `collect()` before computing share price
- Verify that `previewDeposit()` and `previewRedeem()` account for the full economic value of the underlying position including accrued-but-uncollected Uniswap V3 fees

**False Positives**
- The vault intentionally deviates from the ERC-4626 specification in a documented and audited way
- The integration layer wraps the non-compliant vault with an adapter that normalizes behavior for downstream integrators

**Notable Historical Findings**
Astaria's ERC4626Router functions always reverted because the router approved the vault to pull tokens from itself but never pulled the tokens from the user first, breaking the deposit flow entirely. A separate Astaria finding showed that WithdrawProxy allowed redemptions before the public vault had called `transferWithdrawReserve`, enabling early withdrawers to claim funds not yet allocated to the proxy. Maia DAO's vMaia implementation did not correctly reflect locked funds in `maxWithdraw` and `maxRedeem`, causing integrators relying on strict EIP-4626 compliance to compute incorrect withdrawal limits.

---

### Signature and Replay Vulnerabilities (ref: fv-sol-4-c4, fv-sol-4-c10, fv-sol-4-c11)

**Protocol-Specific Preconditions**
- Signed messages omit the chain ID from the digest, allowing signatures from one chain to be replayed on any other chain the protocol is deployed on
- EIP-712 structured hash omits fields that affect execution (price, expiry, deadline), allowing a relayer to substitute values without invalidating the signature
- `ecrecover()` return value is not checked for `address(0)`, accepting null signatures
- The domain separator is computed once at deployment and not recomputed if the contract is deployed on a chain after a fork changes the chain ID

**Detection Heuristics**
- Check all `keccak256(abi.encodePacked(...))` signatures for inclusion of `block.chainid` or use of EIP-712 domain separator that includes `chainId`
- Verify that the EIP-712 type hash includes every execution-relevant field; compare the `abi.encode` arguments in `_hashTypedData` against the struct definition
- Search for `ecrecover()` return value usage without `require(signer != address(0))`
- Check if `DOMAIN_SEPARATOR` is a state variable set at construction; it should be recomputed if `block.chainid != initialChainId`

**False Positives**
- The protocol is deployed on a single chain with no cross-chain plans and the domain separator includes the contract address
- Nonce management is correctly implemented and prevents replay regardless of chain ID absence

**Notable Historical Findings**
Astaria's typed structured data hash for signing commitments was computed incorrectly, such that the hash did not match what signers believed they were authorizing. SeaDrop's `mintSigned` digest was not computed according to EIP-712, and `mintAllowList` and `mintSigned` both lacked replay protection across different drop contracts. Biconomy had a cross-chain signature replay vulnerability where a valid meta-transaction signature on one chain could be replayed on another. Connext's domain separator was not updated after a name/symbol change, potentially invalidating or misidentifying signed messages.

---

### Token Approval Issues (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Protocol calls `IERC20.approve(spender, amount)` on USDT or other tokens that revert on non-zero-to-non-zero allowance changes
- Older OpenZeppelin `safeApprove()` reverts if the current allowance is non-zero, permanently breaking the function after first use
- Approval targets are user-controlled or come from user-supplied calldata, allowing tokens to be approved to attacker addresses
- Allowances are set to `type(uint256).max` and never revoked, leaving the protocol permanently exposed if the approved contract is compromised
- After `NonfungiblePositionManager.decreaseLiquidity()`, the residual approval granted to the NonfungiblePositionManager for `token0` and `token1` is never revoked, leaving the protocol exposed if the position manager contract is later compromised or upgraded

**Detection Heuristics**
- Search for `IERC20(token).approve(spender, amount)` without a preceding `approve(spender, 0)` reset; check if USDT or similar tokens are in scope
- Look for `safeApprove()` calls from OpenZeppelin < v4.9; these revert if current allowance is non-zero
- Check if approval targets are hardcoded/whitelisted or can be influenced by user parameters
- Verify that post-swap or post-operation residual allowances are explicitly revoked
- Verify that token approvals granted to `NonfungiblePositionManager` are reset to zero after each `increaseLiquidity()` or `decreaseLiquidity()` call completes

**False Positives**
- The protocol uses `SafeERC20.forceApprove()` (OpenZeppelin v5+) which handles non-zero-to-non-zero allowance changes correctly
- The token whitelist excludes USDT and any token with non-standard approve behavior
- `safeIncreaseAllowance` and `safeDecreaseAllowance` are used in place of `approve`

**Notable Historical Findings**
LI.FI's proxy facets approved arbitrary user-supplied addresses for ERC-20 tokens in two separate findings, one allowing direct token theft via generic call execution and one where decreasing allowance on an already-non-zero value caused reverts. Astaria's ERC4626Router functions always reverted in part because the approval flow did not account for USDT-style tokens requiring a zero-reset before a new non-zero approval. Notional had a finding explicitly titled "Did Not Approve To Zero First" for a Balancer integration path that would permanently break on second use with USDT.

---

### Fee-on-Transfer Token Handling (ref: fv-sol-2-c7)

**Protocol-Specific Preconditions**
- The protocol calls `token.transferFrom(user, address(this), amount)` and credits `amount` to internal accounting, but the token charges a transfer fee so the contract receives less than `amount`
- Subsequent swaps, loans, or withdrawals rely on the internally recorded amount, which exceeds the actual balance
- Flashloan repayment validation checks a recorded amount rather than measuring the actual balance change
- The protocol does not explicitly reject fee-on-transfer tokens and accepts them without accommodation

**Detection Heuristics**
- Look for `balances[user] += amount` immediately after `transferFrom(user, address(this), amount)` without a balance snapshot
- Check if `IERC20(token).balanceOf(address(this))` is read before and after `transferFrom` to verify actual receipt
- Verify whether USDT (which has a fee flag that can be enabled), STA, or PAXG are in scope or admitted by the token whitelist
- Check flashloan implementations for whether the return check measures `actualBalance >= expectedBalance` vs. comparing against a parameter

**False Positives**
- The protocol explicitly reverts when `actualReceived != amount`, effectively blocking fee-on-transfer tokens at the deposit boundary
- The token whitelist is enforced on-chain and excludes all tokens with transfer fee mechanisms

**Notable Historical Findings**
Blueberry's lending integration with IchiVault did not measure actual received tokens, so fee-on-transfer tokens produced inflated internal balances that diverged from real holdings, understating debt repayment amounts. Ajna's flashloan implementation did not verify the actual end-state balance after the loan callback, meaning a fee-on-transfer token could satisfy the repayment check while leaving the pool short. Numoen and Redacted Cartel each had separate fee-on-transfer findings where deposit or GMX vault deposit paths credited the full `amount` parameter rather than the measured received amount.

---

### Unsafe External Calls (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Aggregator or bridge facets accept a user-supplied call target address and arbitrary calldata, then execute the call while holding approved token balances
- The protocol grants a token approval to a user-controlled address before making a call to that address, enabling the call target to drain the approved tokens
- Diamond proxy fallback functions forward arbitrary calldata to facets without validating the function selector against a whitelist
- Low-level `.call()` return values are not checked, silently ignoring failures

**Detection Heuristics**
- Search for `.call(data)` where `data` or the target address originates from function parameters or calldata
- Check if `IERC20.approve(userSuppliedAddress, amount)` precedes a `.call()` to that same user-supplied address
- Look for bridge facets that accept `bridgeContract` as a parameter and approve tokens to it before calling
- Verify that all `.call()`, `.delegatecall()` return values are checked

**False Positives**
- The call target is from an immutable, on-chain whitelist of trusted protocol addresses
- The call is a `staticcall` and cannot modify any state
- The function is only callable by an admin address protected by a multisig and timelock

**Notable Historical Findings**
LI.FI's GenericBridgeFacet allowed callers to specify arbitrary call targets with arbitrary calldata while the facet held approved token balances from the user, enabling direct token theft. A second LI.FI finding showed that the bridge Axelar facet similarly allowed a malicious external call path that could steal tokens. Biconomy had an arbitrary transaction execution finding where insufficient signature validation allowed a paymaster's ETH balance to be drained via crafted meta-transaction payloads. Optimism's migration path was bricked by sending a message directly to the LegacyMessagePasser, exploiting the absence of a call target guard.
