# Liquidity Manager Security Patterns

> Applies to: concentrated liquidity position managers, Arrakis-style, Gamma-style, Uniswap v3 position wrappers, automated liquidity rebalancers, vault-wrapped LP positions, tick-range managers

## Protocol Context

Liquidity managers sit as an abstraction layer on top of concentrated AMMs such as Uniswap v3, wrapping individual NFT positions into fungible vault shares that represent a range-bound LP strategy. Their correctness depends on external DEX state - tick price ranges, pool slot0, fee accrual checkpoints - that can be manipulated or go stale between rebalance operations. Because rebalancing events trigger collect, burn, and mint sequences on the underlying pool, they accumulate protocol fees and expose multiple re-entry and slippage surfaces within a single transaction. Many protocols additionally wrap positions in ERC-4626 vaults and couple governance, cross-chain bridges, or reward distribution to the same contract surface, compounding the attack area significantly.

## Bug Classes

### Reentrancy (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Collect/rebalance sequences call `nonfungiblePositionManager.collect()` before updating internal share accounting
- ERC-721 callbacks (`onERC721Received`) are triggered when minting or transferring position NFTs mid-transaction
- Wrapped position vaults accept ERC-777 or callback-capable tokens as deposit assets
- Cross-function re-entry paths exist between `rebalance`, `deposit`, and `claimRewards` when they share state variables such as `initialGas` or per-epoch accumulators

**Detection Heuristics**
- Identify all external calls in the rebalance flow: `collect`, `decreaseLiquidity`, `burn`, `mint`, `increaseLiquidity` - check that internal accounting is fully updated before any outbound call
- Search for `transfer`/`safeTransfer` calls preceding state updates in withdraw or close paths
- Check `anyExecute` or bridge callback functions for storage variables written early and read again after re-entry is possible
- Verify `nonReentrant` is applied to all user-facing entry points that touch LP state

**False Positives**
- Protocols that use `nonReentrant` at a router or facet level that covers all entry paths
- Functions that only read state and emit events
- Rebalance functions gated behind a `onlyOperator` modifier that limits who can trigger them

**Notable Historical Findings**
In Maia DAO, `RootBridgeAgent.retrySettlement()` lacked reentrancy protection, allowing an attacker to re-enter and reset `initialGas` storage before the gas payment logic executed, effectively stealing gas budget from the bridge agent. In Carapace, protection sellers exploited the withdrawal sequence to bypass the time-delay mechanism by re-entering `lockCapital` from an external call made mid-loop. In multiple Sudoswap audits, router callbacks and `assetRecipient` hooks were shown to allow re-entry that drained pair funds across swap and NFT batch operations. In Debt DAO, lenders exploited the check-effects-interactions violation in `_close` to drain more tokens than their credit balance by re-entering before the position was deleted.

**Remediation Notes**
Apply `nonReentrant` to every function in the rebalance and withdrawal surface. Follow check-effects-interactions strictly in collect sequences: update all share and fee accumulators before calling `collect` on the NFT manager. For callback-capable tokens used as vault assets, consider a reentrancy lock at the vault deposit/withdraw level. Never cache `initialGas` or epoch state in storage variables readable by re-entrant paths.

---

### Math and Precision Errors (ref: fv-sol-2 / fv-sol-3)

**Protocol-Specific Preconditions**
- Uniswap v3 `slot0` returns `sqrtPriceX96` in Q64.96 fixed-point; incorrect scaling produces catastrophic precision loss
- Fee accumulator updates in `_deposit` and `_withdraw` compound rounding errors across many small operations
- `tickCumulatives` from `observe()` require careful sign handling; hardcoded pool fee values break the TWAP derivation
- Uniswap v3 `swap()` returns signed `int256` amounts where exact-input produces negative output amounts; failing to negate before casting to `uint256` wraps to near-`type(uint256).max`
- `unchecked` blocks used in credit/debt accounting allow underflow when repayment exceeds outstanding principal

**Detection Heuristics**
- Search for `uint256(amount0)` or `uint256(amount1)` immediately following a `IUniswapV3Pool.swap()` call; verify negation is applied
- Check all fee accumulator updates in deposit and withdraw paths for division-before-multiplication
- Audit decimal normalization between token pairs with different `decimals()` values; verify `decimals()` is queried dynamically rather than hardcoded
- Scan `unchecked` subtraction blocks involving user-supplied amounts against internal balances

**False Positives**
- Negation before cast is correct when swap direction guarantees a positive return value
- Precision loss acknowledged as dust when bounded by a documented maximum tick range
- `unchecked` subtraction preceded by a `require(a >= b)` guard

**Notable Historical Findings**
RealWagmi contained a hardcoded pool fee in the `tickCumulatives` calculation, making the TWAP derivation wrong for all non-standard fee tiers. In the same audit, `slot0` was used as the price source for deposit decisions, making the vault trivially front-runnable. Maia DAO's `_gasSwapIn` omitted negation of the signed Uniswap v3 return value, causing the output amount to overflow into an astronomically large number that crashed downstream arithmetic. Notional Leveraged Vaults reported a decimal precision error that inflated prices by several orders of magnitude, enabling unauthorized liquidations and mis-valued vault shares.

**Remediation Notes**
Always negate Uniswap v3 `swap()` signed output before casting: `uint256(-(zeroForOne ? amount1 : amount0))`. Never hardcode fee tiers in TWAP or `tickCumulatives` math; derive them from the pool. Multiply before divide in all reward and fee accumulators. Use `SafeCastLib` for any narrowing cast and verify the upstream value cannot overflow the target type.

---

### Access Control (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Rebalance and range-adjustment functions that modify tick bounds or trigger collect-burn-mint sequences must be operator-only; unrestricted access lets any caller force costly rebalances or drain accrued fees
- Fee withdrawal functions on vault contracts often lack a recipient whitelist, enabling the operator to redirect protocol fees
- Approval-granting functions for external bridge or swap integrations are frequently left unguarded, allowing any caller to approve arbitrary spenders

**Detection Heuristics**
- Audit all `external` or `public` functions that call `collect`, `decreaseLiquidity`, `burn`, `mint`, or `increaseLiquidity` on the position manager
- Check fee setters and protocol fee withdrawal functions for unbounded fee rate parameters
- Search for functions that call `approve` or `safeApprove` on vault tokens where the spender address is caller-supplied
- Verify that `initialize` functions can only be called once and by the expected deployer or factory

**False Positives**
- Permissionless rebalance functions that are correct by design when tick-drift conditions are enforced on-chain before execution
- Operator-role functions where the operator is a secured multisig with timelocks

**Notable Historical Findings**
Maia DAO's `BoostAggregator` allowed the owner to set fees to 100%, directing all user rewards to the owner. The same audit found that `withdrawProtocolFees()` could be called to drain all accumulated rewards without a recipient whitelist. In LI.FI, `setApprovalForBridges` was callable by any address and could approve any token to any bridge contract, enabling total fund drainage. In Talos (Maia DAO), protocol fees accumulated inside vault contracts with no corresponding `withdrawProtocolFees` function, permanently locking them.

**Remediation Notes**
Gate all rebalance entry points with `onlyOperator` or equivalent. Add explicit upper bounds to all admin-settable fee parameters. Restrict approval-granting functions to owner-only and require the spender to be on a whitelist. Add a `withdrawProtocolFees` function to all vault contracts that accumulate fees. Never use caller-supplied addresses as sole authorization evidence.

---

### Logic Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Fund Lock: rebalance operations that transfer LP NFTs or underlying tokens through intermediate steps can strand assets if a step reverts or a destination contract lacks a `receive()` fallback
- Fee/Royalty Distribution in LP context: fee double-counting between collect and mint steps; protocol fees trapped inside position vault contracts without a withdrawal mechanism
- Tick-range rebalance flaws: strategy contracts that compute new tick ranges without validating against current `slot0` or TWAP allow ranges to be set outside valid Uniswap tick bounds; `init()` and `rebalance()` paths often lack slippage guards on the resulting liquidity amounts

**Detection Heuristics**
- Trace every fund flow through rebalance: verify that collect proceeds, burnt liquidity, and minted liquidity deltas are fully reconciled with vault share accounting
- Check if `amount0Min` / `amount1Min` parameters on `increaseLiquidity` and `decreaseLiquidity` calls are set to zero (hardcoded) or derived from on-chain spot price
- Look for multi-step operations (swap-then-bridge, collect-then-reinvest) where partial failure at step N does not return step 1..N-1 assets to users
- Verify excess `msg.value` is refunded in payable rebalance or deposit functions

**False Positives**
- Zero minimum amounts are acceptable when the caller is a trusted operator contract that enforces slippage off-chain
- Intermediate custody during rebalance is acceptable when the full sequence executes atomically in a single transaction with no external calls that can revert midway

**Notable Historical Findings**
Maia DAO Talos vault contracts trapped protocol fees permanently because the fee accumulation logic in `rerange()` called `collect()` but there was no function to withdraw the resulting balance. In LI.FI, cross-chain operations that routed through Axelar had no recovery path for failed destination executions, permanently locking bridged tokens. In multiple Maia DAO bridge agent findings, partial failure during multi-step settlement left user deposits in an irrecoverable intermediate state without a valid nonce for retry. RealWagmi's `rebalanceAll` had no slippage protection on either the withdraw or the deposit leg of the rebalance, making it profitable to sandwich.

**Remediation Notes**
Ensure every `collect` call is matched by a corresponding fee accounting update and that accumulated protocol fees have an owner-callable withdrawal path. Set `amount0Min` and `amount1Min` using TWAP-derived bounds rather than zero. Implement recovery maps for cross-chain operations keyed by sender and transfer timestamp. Verify tick bounds against `TickMath.MIN_TICK` / `MAX_TICK` and the pool's `tickSpacing` before submitting to the position manager.

---

### ERC-4626 Vault Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Liquidity manager vaults that wrap LP positions in ERC-4626 inherit share price manipulation risk at first deposit, but additionally face the edge case where `totalAssets()` drops to zero if all liquidity is burned and fees not yet collected
- `maxWithdraw` and `maxRedeem` must account for rebalance lock periods and operator-imposed withdrawal gates; returning non-zero when the vault is in a rebalancing state violates EIP-4626 and causes integration failures
- Conversion rate mechanisms relying on governance token balances within the vault (e.g., vMaia) are vulnerable to dilution by internal minting sequences

**Detection Heuristics**
- Check that `previewDeposit` and `previewRedeem` do not divide by zero when `totalAssets()` is zero but `totalSupply()` is non-zero (possible after a full liquidity burn)
- Verify `maxWithdraw` returns zero during rebalance lockout windows and not just during explicit pause states
- Check `convertToShares` rounds down and `convertToAssets` rounds down, favouring the vault
- Audit any logic that mints extra governance or utility tokens inside the vault for conversion rate side-effects

**False Positives**
- Virtual shares offset (OpenZeppelin `_decimalsOffset`) correctly mitigates first-depositor inflation and is a known-good pattern
- Non-zero `maxWithdraw` during a pause is acceptable when the pause only affects new deposits, not existing withdrawals

**Notable Historical Findings**
Maia DAO's `vMaia` `maxWithdraw` and `maxRedeem` did not return zero during the monthly withdrawal window restriction, violating EIP-4626. The same audit found that internal governance token minting within the vault disrupted the conversion rate mechanism, allowing dilution of existing share holders. In Y2k Finance, the vault was verified non-compliant with EIP-4626 because `previewDeposit` did not account for the zero-supply edge case. Carapace reported a freeze condition where `totalSTokenUnderlying` dropped to zero while shares remained outstanding, causing all subsequent deposit previews to return zero.

**Remediation Notes**
Guard `previewDeposit` and `previewRedeem` against zero-`totalAssets` by treating the vault as 1:1 when either supply or assets are zero. Override `maxWithdraw` and `maxRedeem` to reflect all protocol-level restrictions including rebalance locks and epoch gates. Use virtual shares (offset by at least `10^decimalsOffset`) to prevent first-depositor inflation without relying on minimum deposit enforcement.

---

### Slippage and MEV (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Automated rebalancers must trigger `decreaseLiquidity` → `collect` → `mint` with no user present to supply slippage bounds; protocols that hardcode `amount0Min = 0` on these calls are fully sandwichable
- `slot0.sqrtPriceX96` is used as the reference price for computing new tick range mid-points; this is trivially manipulated within a block
- `deadline: block.timestamp` on position manager calls provides no real deadline protection for pending transactions sitting in the mempool
- Publicly callable premium accrual or reward distribution functions can be sandwiched to extract value from the resulting state change

**Detection Heuristics**
- Grep for `amount0Min: 0` and `amount1Min: 0` in `IncreaseLiquidityParams` and `DecreaseLiquidityParams` structs
- Search for `slot0()` calls where the result feeds into a swap price limit or a tick range calculation
- Check all swap router calls for `deadline` parameter sourced from `block.timestamp` only, with no user-supplied expiry
- Look for permissionless epoch-advance or accrual functions that materially change token exchange rates

**False Positives**
- `deadline: block.timestamp` is acceptable when the function is restricted to a trusted keeper or operator that submits atomically
- Zero minimum amounts are acceptable when the caller validates slippage in the same transaction using a pre/post balance check

**Notable Historical Findings**
RealWagmi's `rebalanceAll` set both `amount0Min` and `amount1Min` to zero for both the withdraw and deposit legs, making every rebalance a profitable sandwich target. Maia DAO's `TalosBaseStrategy.init()` similarly omitted slippage protection entirely during initial liquidity provisioning, allowing an attacker to front-run the initialization and steal a portion of deposited assets. The Maia DAO `_gasSwapIn` used `slot0` to derive `sqrtPriceLimitX96`, making every gas swap trivially manipulable. Carapace's `accruePremiumAndExpireProtections()` was exploitable via sandwich because it was public and modified the protection pool exchange rate.

**Remediation Notes**
Never hardcode `amount0Min = 0` on operator-triggered rebalances; derive minimum amounts from a TWAP with a configurable tolerance (e.g., 1%). Replace `slot0` price references with `observe()`-based TWAP for all swap price limits used in rebalance logic. Accept a caller-supplied `deadline` parameter distinct from `block.timestamp` for any operation that can remain in the mempool. Restrict premium accrual and distribution functions to keepers with a minimum interval between calls.

---

### Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Protocols that iterate over all active positions to accrue premiums or compute epoch totals are vulnerable when position count grows without bound
- External calls to lenders, protection buyers, or reward recipients inside loops allow a single malicious actor to block the entire iteration by deploying a reverting receiver
- Rebalance or liquidation functions that depend on full-collection iteration over positions cannot complete if the collection has been grown by a griefing attacker

**Detection Heuristics**
- Search for `for` loops whose upper bound is `activePositions.length` or equivalent dynamic storage array length
- Verify that any user can increase the iterable collection size for a cost lower than the gas saved by disruption
- Check if liquidation or epoch-settlement functions can be individually skipped or if a single revert aborts the entire batch
- Look for external token transfers to arbitrary recipient addresses within loop bodies

**False Positives**
- Collections bounded by a protocol constant below the block gas limit
- Batch functions with pagination parameters that allow the caller to split work across multiple transactions

**Notable Historical Findings**
Carapace's `accruePremiumAndExpireProtections` iterated over an unbounded array of active protections; an attacker could cheaply create enough positions to push the function past the block gas limit, freezing premium accrual permanently. Maia DAO's `_decrementWeightUntilFree` contained a possible infinite loop that could halt gauge weight removal. Debt DAO's lender callback pattern allowed a malicious lender to deploy a reverting contract as their address, preventing any position closure. Accountable's withdrawal queue was permanently blocked by a sequence of cancelled redeem requests that left the queue head pointing at a non-processable entry.

**Remediation Notes**
Add a `MAX_BATCH_SIZE` constant and paginate all collection-iterating functions. Use a pull-payment pattern for lender and protection buyer payouts rather than pushing inside loops. Enforce a minimum cost to add entries to iterable collections. Design epoch-settlement functions to be skippable per-entry so a single bad actor cannot block the entire epoch.

---

### Oracle / Price Feed Manipulation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- `slot0.sqrtPriceX96` is the most-used price source in Uniswap v3 position managers and is manipulable within a single block with sufficient capital
- TWAP derivation from `tickCumulatives` requires correct fee-tier-specific tick spacing; hardcoding the fee causes miscalculation for pools with non-default fees
- Chainlink feeds used for vault share valuation or rebalance triggers must be validated for staleness and decimal consistency with the paired asset feed

**Detection Heuristics**
- Find all `slot0()` calls; determine if the result is used for any valuation, swap limit, or liquidation decision
- Verify that `latestRoundData()` return values are fully validated: `price > 0`, `answeredInRound >= roundID`, `block.timestamp - updatedAt < MAX_STALENESS`
- Check that `priceFeed.decimals()` is queried dynamically before any normalization arithmetic
- Audit compositions of two price feeds to confirm intermediate normalization to a common scale before division

**False Positives**
- `slot0` used purely for range visualization in a `view` function with no on-chain economic effect
- Chainlink staleness tolerance intentionally relaxed for ETH/USD feeds with documented justification

**Notable Historical Findings**
RealWagmi used `slot0` for both deposit price decisions and tick range calculations, enabling profitable sandwich attacks on every deposit and rebalance. Y2k Finance's `PegOracle` composed two Chainlink feeds without normalizing decimals, causing the ratio to be off by a factor of `10^10` for 18-decimal feeds. Maia DAO used `slot0` to derive `sqrtPriceLimitX96` in its gas swap path, making the swap price trivially manipulable. Notional Leveraged Vaults reported that wrong decimal precision in vault share valuation inflated reported prices and caused incorrect liquidation thresholds.

**Remediation Notes**
Replace `slot0` with a TWAP derived from `IUniswapV3Pool.observe()` for all economically consequential price reads; use a minimum observation window of at least five minutes. Validate all Chainlink responses against a staleness threshold. Normalize both feeds to 18 decimals before composing them into a ratio. Query `decimals()` dynamically and validate that the result is within expected bounds before using it in arithmetic.

---

### Fee and Royalty Distribution in LP Context (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- LP fee collection from Uniswap v3 positions (`nonfungiblePositionManager.collect`) produces two token amounts that must be correctly split between protocol, operators, and depositors
- Fee accounting in `_deposit` and `_withdraw` must be updated atomically with share minting/burning; deferred updates allow new depositors to claim a share of fees they did not earn
- Protocol fee accumulators inside position vault contracts often have no corresponding withdrawal path, causing permanent fund lock

**Detection Heuristics**
- Trace the output of every `collect()` call: verify the two token amounts are accounted for exactly once in the vault's internal fee ledger
- Check if the protocol fee percentage setter has an upper bound; an unbounded setter allows the operator to extract 100% of collected fees
- Verify that a `withdrawProtocolFees` function exists and is restricted to a whitelisted recipient
- Check if fee updates in `_deposit` and `_withdraw` run before share changes to prevent new depositors claiming historic fees

**False Positives**
- Protocols where all collected fees are immediately reinvested and no protocol fee is taken
- Vaults that distribute fees proportionally at the share level with no separate accumulator

**Notable Historical Findings**
RealWagmi reported multiple fee calculation errors: fees were incorrectly updated in both `_deposit` and `_withdraw` functions, causing new depositors to dilute accrued fees and existing depositors to receive less than their entitlement. Maia DAO's Talos vault contracts permanently trapped protocol fees because `rerange()` called `collect()` but no withdrawal mechanism existed. In Golom, the protocol fee was double-counted - subtracted from seller payout and added to buyer cost simultaneously - doubling the effective fee rate. Carapace's sandwich vulnerability in `accruePremiumAndExpireProtections` allowed an attacker to enter and exit just before and after premium accrual, extracting fees intended for long-term protection sellers.

**Remediation Notes**
Update fee accumulators before minting or burning shares in every deposit and withdraw path. Add an explicit `withdrawProtocolFees(address token, address recipient) external onlyOwner` function to all position vaults. Cap the protocol fee rate with an immutable constant. Validate that `collect()` output tokens are reconciled with the vault's internal token0/token1 balance tracking within the same transaction.

---

### Fund Lock in Position NFTs (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- LP position NFTs represent illiquid, range-bound capital; if the NFT is transferred to a contract that does not implement `onERC721Received`, all underlying liquidity becomes permanently inaccessible
- Multi-step rebalance operations that burn a position NFT and attempt to mint a new one can fail at the mint step, leaving the vault without a valid position NFT and the underlying tokens sitting in the vault contract without a way to re-enter a position
- Cross-chain bridge operations initiated from a liquidity manager during yield-routing or fee-compounding have no recovery path if the destination execution fails

**Detection Heuristics**
- Check what happens to vault state if `mint` fails after a successful `burn` in the rebalance path; verify there is an emergency recovery function that can re-enter a position using the held token balances
- Trace excess `msg.value` paths in payable rebalance or deposit functions; unspent ETH must be refunded or tracked
- Check all cross-chain dispatch calls for a corresponding recovery or retry mechanism indexed by the originating sender

**False Positives**
- Vaults where rebalance is atomic (burn+mint in same call to position manager) and the manager reverts the entire call on failure
- Protocols with a `rescueTokens` or `emergencyWithdraw` owner function that can recover stranded assets

**Notable Historical Findings**
Maia DAO reported multiple cases where bridge agent multi-step operations (deposit → bridge → settle) left user funds in irrecoverable intermediate states when any step failed, with no valid nonce available for retry. LI.FI's Axelar integration transferred tokens cross-chain with no recovery mechanism for failed destination execution. In Notional Leveraged Vaults, Lido and EtherFi withdrawal limitations caused `_finalizeCooldown` to revert in edge cases, permanently bricking withdrawal for affected users. The LI.FI `WithdrawFacet` used `payable.transfer()` for ETH sends, which fails silently for contract recipients with non-trivial fallback logic, locking ETH inside the facet.

**Remediation Notes**
Make rebalance atomic by using a single `multicall` to the position manager where possible. Add an emergency function `recoverPosition(uint256 amount0, uint256 amount1, int24 tickLower, int24 tickUpper)` callable only by the owner when no active position exists. Replace all `payable.transfer()` with `(bool ok,) = recipient.call{value: amount}("")` and require `ok`. Implement a keyed recovery map for all cross-chain transfers indexed by sender and block timestamp.

---

### Non-Standard ERC-20 Token Handling (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Vaults that accept arbitrary deposit tokens without enforcing a whitelist are exposed to fee-on-transfer tokens that reduce actual received amounts below recorded deposits
- Rebasing tokens (stETH, aTokens) used as underlying assets cause vault `totalAssets` to drift from internal accounting over time
- USDT-style tokens require the allowance to be zeroed before setting a new non-zero approval; `safeApprove` reverts if called with a non-zero existing allowance

**Detection Heuristics**
- Search for `transferFrom` calls where the `amount` parameter feeds directly into state accounting without a before/after balance measurement
- Check for `safeApprove` calls that may execute when residual allowance is non-zero (e.g., after a partial bridge consumption)
- Verify that `totalAssets()` in any ERC-4626 wrapper over staked or rebasing tokens updates to reflect rebasing rather than using a cached deposit sum

**False Positives**
- Vaults with an explicit token whitelist that excludes fee-on-transfer and rebasing tokens
- `forceApprove` (OZ v5) or explicit zero-then-set patterns that handle USDT correctly

**Notable Historical Findings**
Y2k Finance's vault accepted fee-on-transfer tokens in multiple critical paths, causing the depeg trigger that transferred the full recorded balance to revert because actual balance was lower. Cally vaults allowed rebasing tokens, causing the vault to silently accumulate or lose value relative to share accounting between operations. Notional Leveraged Vaults reported that EtherFi rebase tokens transferred 1–2 wei less than requested, causing `_initiateWithdrawImpl` to revert during the withdrawal finalization. In Backed Protocol, `PaprController` paid Uniswap swap fees from protocol funds rather than the user's input, effectively subsidizing trades from vault reserves.

**Remediation Notes**
Measure actual received amounts using before/after `balanceOf` snapshots on every `transferFrom`. Exclude fee-on-transfer and rebasing tokens via an explicit allowlist enforced in the token registration function. Use `forceApprove` or zero-then-set for all allowance updates to bridge and swap integrations. Document clearly in the vault interface which token behaviors are not supported.

---

### Reward Distribution (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Gauge-based reward systems that couple LP position size to voting-escrow token balances require atomic updates to both the position and the gauge weight; desyncing these creates phantom gauge weight or loss of boost
- New LP depositors who are not initialized with the current `rewardPerToken` accumulator immediately earn a share of all historically undistributed rewards
- Removing a bribe flywheel from a gauge without removing the reward asset from the rewards depot leaves orphaned reward tokens that can be claimed by front-running the next `addBribeFlywheel` call
- Gauge reward queuing must occur every epoch; missed epochs permanently slash the unqueued rewards

**Detection Heuristics**
- Check that `deposit` and `mint` functions call `_updateReward(account)` before minting new shares
- Look for `notifyRewardAmount` functions callable repeatedly with dust amounts that extend the reward period and dilute rate
- Audit gauge deprecation and re-addition sequences for epoch-boundary accounting gaps
- Verify that `userRewardPerTokenPaid` is initialized to `rewardPerTokenStored` at the moment of first deposit, not left at zero

**False Positives**
- Protocols where new depositors explicitly share in undistributed rewards by documented design
- Reward distribution guarded by Merkle proofs computed off-chain at epoch snapshot time

**Notable Historical Findings**
Maia DAO reported that re-adding a deprecated gauge before calling `updatePeriod()` in a new epoch left some rewards permanently unclaimable due to an off-by-one in the epoch boundary check. Removing a `BribeFlywheel` from a gauge did not remove the associated reward asset from the depot, allowing a malicious user to front-run the next `addBribeFlywheel` call and steal all accumulated bribe rewards. GrowthDeFi WHEAT showed that new depositors immediately received a share of rewards accumulated before their deposit, which was exploited by sandwiching `gulp()` calls. Y2k Finance's `StakingRewards` reward rate could be dragged out indefinitely by calling `notifyRewardAmount` with tiny amounts, diluting the effective rate for existing stakers.

**Remediation Notes**
Call `_updateReward(msg.sender)` as the first line of every `deposit`, `mint`, and `withdraw` function. Initialize `userRewardPerTokenPaid[account]` to `rewardPerTokenStored` at first stake. Add a minimum reward notification amount to prevent rate dilution griefing. Design gauge deprecation to atomically remove both the gauge and all associated bribe flywheel reward assets. Ensure epoch-advance functions can be called permissionlessly to prevent missed-epoch slashing due to keeper failure.
