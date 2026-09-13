# On-Chain Insurance Security Patterns

> Applies to: on-chain insurance protocols, coverage protocols, risk pools, parametric insurance, claims processing, Nexus Mutual-style, InsurAce-style

## Protocol Context

On-chain insurance protocols pool capital from coverage providers, underwrite risk against defined trigger conditions, and pay out claims via smart contract execution with no human intermediary. The attack surface spans three interacting systems: vault accounting (EIP-4626 share math, deposit/withdrawal queues), oracle-driven trigger conditions (price depegs, protocol hacks, parametric events), and staking or reward distribution that incentivizes capital providers over long epochs. Because insurance payouts must be reliable under adversarial conditions-including the very events they insure against-precision errors, oracle manipulation, and queue deadlocks carry outsized severity compared to typical DeFi protocols.

---

### Reentrancy in External Calls (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Redemption function executes a user-supplied swap path (e.g., Uniswap V2 multi-hop) to convert yield tokens before updating `s_yieldTokenBalance`; a malicious intermediary token in the path can reenter the redemption function, causing double subtraction from the yield token balance
- Fee distribution pushes tokens to the manager address in a loop; if the manager is a contract with an ERC777 `tokensReceived` hook, it can reenter before the loop finishes and claim more than its share
- ERC1155 safe transfer in a reward distribution loop invokes `onERC1155Received` on each recipient; a malicious recipient can block all subsequent distributions or reenter the distributor

**Detection Heuristics**
- Search for external calls (`safeTransfer`, `.call`, swap router invocations) that precede state variable updates in redemption, withdrawal, or fee-claiming functions
- Identify functions missing `nonReentrant` that interact with user-controlled token addresses or swap paths
- Look for user-controlled exchange data parameters (`bytes calldata redeemData`) that are decoded into swap paths; check if path length is validated to prevent malicious intermediary tokens
- Verify that vault, router, and request manager contracts use a common reentrancy lock, not independent locks that allow cross-contract reentry

**False Positives**
- All external calls made only to known, audited contracts (WETH, Aave aTokens) that do not propagate arbitrary callbacks
- Swap paths validated to contain exactly two tokens (single-hop), preventing malicious intermediary insertion
- Functions that strictly follow checks-effects-interactions without any external call before state updates

**Notable Historical Findings**
Notional Finance's `redeemNative()` executed a swap through a user-supplied path before updating `s_yieldTokenBalance`; a malicious intermediary token could reenter the function, causing the balance to be decremented twice per actual redemption and permanently freezing funds in the vault. Gauntlet's managed vault allowed a malicious manager to cause vault fund inaccessibility through ERC1155 callback reentrancy in distribution loops. Bridge Mutual's LiquidityMining contract had an ERC1155 reentrancy issue that allowed single-token transfers to trigger the full single-receive callback, creating unexpected state transitions. Notional Finance additionally discovered that nested `nonReentrant` guards on allocation wrappers could cause legitimate operations to revert, a secondary impact of an overly broad reentrancy guard scope.

**Remediation Notes**
- Add `nonReentrant` to all redemption, withdrawal, and fee-distribution entry points; if multiple contracts share state, they must share or coordinate a single reentrancy lock
- Validate swap paths in `redeemData` to allow only single-hop swaps (exactly two token addresses) before executing any external trade
- Replace push-based fee distribution with a pull pattern: accumulate fee entitlements in a mapping during accounting, and let managers claim via a separate `nonReentrant` function

---

### Precision Loss and Rounding Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Fee calculation uses `amount / 10000 * feeRate` order, which evaluates to zero for amounts below 10000 scaled by `feeRate`
- Reward rate is computed as `reward / rewardsDuration` where `rewardsDuration` is a multi-year value; integer truncation discards up to `rewardsDuration - 1` tokens per reward period, permanently locking them
- `accrueInterest()` is callable at arbitrary frequency; single-second calls compute `principal * rate * 1 / SECONDS_PER_YEAR` which rounds to zero for principals below a threshold, silently zeroing interest for small positions
- EIP-4626 `price()` function divides by `totalSupply()` which reverts or returns an incorrect value when the vault is empty

**Detection Heuristics**
- Search for `a / b * c` expressions in fee, reward, or price functions; flag division before multiplication
- In reward notifiers, compute `rewardRate * rewardsDuration` and compare against `reward`; any shortfall is permanently lost to rounding
- Find interest accrual functions callable without a minimum elapsed time; check whether a per-second interest amount can evaluate to zero for the smallest supported position
- Search for `totalAssets() / totalSupply()` or equivalent without a zero-supply guard
- In price ratio calculations between oracle feeds with different decimals, verify normalization precedes any arithmetic comparison

**False Positives**
- Protocols using PRBMath, DSMath, or similar fixed-point libraries consistently throughout all arithmetic paths
- Rounding errors provably below one wei for all realistic input ranges and documented as accepted dust
- `totalSupply == 0` structurally prevented by a minimum deposit, dead shares, or initial liquidity seeded at deployment

**Notable Historical Findings**
Y2k Finance's staking rewards suffered significant precision loss because the reward rate division discarded a material fraction of tokens over a four-year reward period, and a separate finding showed receivers getting nothing when `amount / 10000 * feeRate` evaluated to zero for small deposits. Accountable Protocol's open-term loan accumulated interest in per-second increments; because `accrueInterest()` could be called at any frequency, high-frequency callers reduced effective interest to zero and the loan principal could not be repaid once it reached zero due to a division-by-zero revert. Notional Finance exposed a division-by-zero in `price()` when `totalSupply == 0` immediately after vault initialization, blocking the first depositor's preview calculation.

**Remediation Notes**
- Always multiply before dividing: replace `amount / 10000 * feeRate` with `amount * feeRate / 10000`
- Store reward rates in a higher-precision scaled integer (`reward * PRECISION / duration`); scale back to base units only at claim time to preserve per-period precision
- Enforce a minimum accrual interval (e.g., one hour) in `accrueInterest()` to prevent compounding rounding loss from high-frequency calls
- Handle `totalSupply() == 0` in `price()` by returning a default value (e.g., `1e18`) rather than dividing

---

### Staking Reward Calculation Errors (ref: fv-sol-3)

**Protocol-Specific Preconditions**
- `notifyRewardAmount` called mid-period dilutes remaining rewards across the extended duration instead of layering them cleanly; the balance check compares contract token balance against future obligations but does not subtract already-earned but unclaimed rewards, overstating available funds
- Shared reward token contract serves multiple pools; balance queries return the total contract balance rather than the pool-specific allocation, making each pool appear to have access to all reward tokens
- After vault epoch expiration, `getReward()` continues to allow claims against the next epoch's allocation rather than requiring rollover enrollment
- `recoverERC20()` is callable by the owner without excluding the reward token, functioning as an undisclosed withdrawal backdoor

**Detection Heuristics**
- In `notifyRewardAmount`, trace the balance check: does it subtract `totalUnclaimed()` from `rewardsToken.balanceOf(address(this))` before comparing against `rewardRate * rewardsDuration`?
- Find protocols with a single contract holding rewards for multiple pools; check if reward balance queries are scoped per pool via a `poolId` mapping or simply use `balanceOf(address(this))`
- Look for `getReward()` or `claimRewards()` functions without epoch expiry guards
- Search for `recoverERC20` or equivalent rescue functions; verify they cannot be used to extract reward or staking tokens

**False Positives**
- Protocols that call `updateReward(address(0))` as the first line of `notifyRewardAmount`, ensuring all accrued rewards are checkpointed before the new rate is set
- Separate contract deployments per pool with isolated token balances
- Dedicated vesting contracts that hold reward tokens and release them over a schedule independent of the staking contract

**Notable Historical Findings**
Y2k Finance's `StakingRewards` had a reward rate dilution bug where calling `notifyRewardAmount` mid-period extended the reward duration and reduced the effective rate, and a separate `recoverERC20()` function allowed the owner to withdraw reward tokens, effectively acting as a rug vector. Notional Finance found that claims from the Curve gauge were blocked by a nested reentrancy guard, making rewards permanently inaccessible. Neptune Mutual's staking system conflated reward balances across multiple pools, meaning large rewards deposited for one pool were visible to reward calculators in other pools, enabling disproportionate claims. Audius's reward calculation was incorrect when a pending decrease-stake request was in flight, causing the protocol to distribute more rewards than intended.

**Remediation Notes**
- Before computing the new rate in `notifyRewardAmount`, call `_updateReward(address(0))` to checkpoint all accrued rewards; then compute `available = balance - _totalUnclaimed()` and assert `newRate * duration <= available`
- Deploy separate reward token contracts per pool or maintain a `poolRewardBalances[poolId]` mapping that is decremented on each deposit and claim
- Add `require(block.timestamp <= epochEnd, "Epoch expired")` to `getReward()`; provide a rollover function for transferring unclaimed rewards to the next epoch

---

### Privileged Role Abuse (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Owner can call `setController(newController)` which immediately migrates all vault funds to an address they control with no timelock or multi-party approval
- `sweep(token, amount)` does not exclude the vault's own BPT (Balancer Pool Token) or underlying asset, allowing the owner to drain the liquidity pool
- A `withdrawRedundant` function callable by keeper or controller allows withdrawing tokens without checking whether they belong to users
- Registry or factory admin can register arbitrary market contract addresses; registered markets gain the ability to call `addValue()` on the vault, enabling fund transfers from any user who has approved the vault

**Detection Heuristics**
- Find `setController`, `setManager`, or `setKeeper` functions; check if they are behind a timelock and whether they trigger fund migration
- Search for `sweep` or `recoverERC20` functions; trace whether they include restrictions on pool tokens, underlying assets, or staking tokens
- Look for `withdrawRedundant`, `emergencyWithdraw`, or similar functions with weak access control (keeper or single EOA) that can move protocol-critical tokens
- Identify registry patterns where an admin-registered address gains `onlyMarket`, `onlyStrategy`, or similar roles that allow interaction with user funds

**False Positives**
- Privileged roles held by a multi-sig with adequate threshold and a mandatory timelock delay
- `sweep` functions that explicitly iterate over a `managedTokens` array and revert if the sweep target matches any managed token
- Protocols in early bootstrap phase with disclosed centralization and a public schedule for decentralization

**Notable Historical Findings**
InsureDAO had at least four separate privileged-role exploits: `setController()` migrated all funds to a new address without any guard, `withdrawRedundant()` allowed the keeper to drain user deposits, wrong permission control on a separate function allowed the admin to steal funds directly, and a malicious registry admin could register a market that drained any vault. Y2k Finance's `changeController()` and `recoverERC20()` were independently identified as rug vectors in the same codebase. Gauntlet's vault manager could call `setSwapFees` to create internal arbitrage opportunities at the expense of depositors, and `sweep()` did not exclude BPT tokens, enabling the treasury to drain the Balancer pool.

**Remediation Notes**
- Gate all fund-migrating calls (`setController`, `setManager`) behind a two-step propose-then-accept pattern with at minimum a 48-hour timelock
- In `sweep()`, iterate `managedTokens` and revert if the target token matches any pool token, underlying asset, or staking token
- Replace keeper-callable `withdrawRedundant` with an emergency function requiring multi-sig approval and restricted to genuinely excess tokens (balance minus all user liabilities)

---

### ERC Standard Non-Compliance (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Vault claims EIP-4626 compliance but is missing `mint()` and `redeem()` functions, or `maxDeposit()` returns `type(uint256).max` even when deposits are paused or the epoch is closed
- `totalAssets()` returns only `balanceOf(address(this))`, excluding assets paid out during a depeg event or locked in an outstanding claim, understating the vault's true liability
- `previewDeposit()` does not subtract the deposit fee from its return value, causing integrators to over-estimate share amounts
- `safeApprove` used for USDT-like tokens reverts when the current allowance is non-zero, blocking any deposit or withdrawal path that calls `approve` more than once
- ERC1155 `safeTransferFrom` is used in a distribution loop; any recipient contract that reverts its `onERC1155Received` callback blocks all subsequent distributions in the loop

**Detection Heuristics**
- Check the deployed ABI against the full EIP-4626 interface: `deposit`, `mint`, `withdraw`, `redeem`, `totalAssets`, `convertToShares`, `convertToAssets`, `maxDeposit`, `maxMint`, `maxWithdraw`, `maxRedeem`, `previewDeposit`, `previewMint`, `previewWithdraw`, `previewRedeem`
- For each `max*` function, verify it returns 0 when the corresponding operation is blocked (paused, epoch closed, deposits locked)
- For each `preview*` function, verify fee deduction is reflected in the return value
- Search for `safeApprove` calls; replace with `forceApprove` (OZ v5) or a zero-then-set pattern
- Search for ERC1155 `safeTransferFrom` in loops; assess whether a single revert can block all subsequent recipients

**False Positives**
- Protocols that explicitly document deviations from EIP-4626 and do not present themselves as standard-compliant vaults
- Integrations that use the vault only internally and have no external EIP-4626 aggregator dependencies
- Reward distribution to a controlled set of known-compliant receiver contracts

**Notable Historical Findings**
Y2k Finance's `SemiFungibleVault` claimed EIP-4626 compliance but was missing `mint()` and `redeem()`, had non-compliant `maxWithdraw()` that ignored pause state, and did not include depeg payouts in `totalAssets()`, making share price calculations incorrect during the protocol's primary trigger scenario. Bridge Mutual's LiquidityMining contract could not accept single ERC1155 tokens because it did not implement `onERC1155Received`, blocking a core interaction path. Accountable Protocol's vault had an invalid `maxWithdraw()` check that could allow withdrawals to exceed actual holdings. Multiple protocols independently discovered that `safeApprove` with USDT caused silent reverts in deposit paths that ran after any partial approval.

**Remediation Notes**
- Inherit from OpenZeppelin's `ERC4626` base contract rather than implementing the interface from scratch; override only the functions that require protocol-specific logic
- In `maxDeposit` and `maxWithdraw` overrides, return 0 as the first branch if `paused()`, if the epoch is outside its active window, or if any other blocking condition is true
- Replace all `safeApprove` calls with `token.forceApprove(spender, amount)` (OpenZeppelin v5+)

---

### Missing Input Validation (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Constructor or initializer accepts `manager_`, `validator_`, `noticePeriod_`, and `managementFee_` without validating that addresses are non-zero, that cross-contract invariants hold (e.g., validator token count matches vault token count), or that numeric parameters fall within safe ranges
- `noticePeriod_` has only a maximum check (`<= MAX`), allowing zero, which enables instant finalization and bypasses the intended withdrawal protection
- L2 deployments do not check Arbitrum/Optimism sequencer uptime in price validation helpers, allowing stale prices from before a sequencer outage to be used as current
- Signature replay is possible because signed messages do not include a nonce; the same signature can be submitted multiple times

**Detection Heuristics**
- Review every constructor and `initialize()` function; check each address parameter against `address(0)` and against related contracts' state (e.g., `require(validator.count() == tokens.length)`)
- For numeric parameters, verify both minimum and maximum bounds are enforced; a missing minimum is as dangerous as a missing maximum
- For `string` parameters with functional significance (descriptions, URIs), check `require(bytes(param).length > 0)`
- On L2 deployments, search for `latestRoundData` calls without a preceding sequencer uptime feed check
- Find all signature verification paths; confirm each signs over at minimum `(target, data, nonce, chainId, verifyingContract)`

**False Positives**
- Parameters validated downstream by third-party contracts (e.g., Balancer's own fee validation rejects out-of-range values)
- Factory contracts that perform cross-contract validation centrally at deployment, preventing misconfigured pairs from ever being created
- Immutable parameters set by a trusted deployer in a controlled deployment process with off-chain verification

**Notable Historical Findings**
Gauntlet's AeraVault had two distinct input validation failures in the same constructor: the validator's token count could mismatch the vault's asset count (causing all withdrawals to revert with an array index error), and multiple constructor parameters including manager address and notice period had no minimum constraints. InsureDAO had a signature replay vulnerability because policy purchase signatures did not include a nonce, allowing the same signed transaction to purchase multiple policies at the same price. Bridge Mutual's liquidity mining contract had no whitelist check, allowing anyone to claim all mining rewards by providing zero DAI. Audius's governance contract accepted quorum parameters that could be set so low that sybil accounts trivially reached quorum.

**Remediation Notes**
- Use a factory pattern for deploying coordinated contract pairs; validate cross-contract invariants (validator count, token lists) inside the factory before returning contract addresses
- Every numeric parameter with a practical minimum must assert `require(value >= MIN_VALUE, "...")` alongside any maximum check
- Use EIP-712 with per-user nonces for all signed messages; increment `nonces[signer]++` on every successful verification

---

### Fee-on-Transfer Token Incompatibility (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Insurance protocol accepts coverage tokens that may implement, or later enable, transfer fees (USDT's fee switch, protocol-controlled ERC20s)
- `addValue(amount, from, beneficiary)` credits `amount` to the beneficiary's attribution but the contract received `amount - fee` due to a transfer tax, overstating the beneficiary's share
- Withdrawal path calls `tokens[i].safeTransfer(owner(), amounts[i])` after receiving tokens from a pool; if the pool itself deducted fees on its transfer, the contract does not hold `amounts[i]` and the transfer reverts, blocking all withdrawals

**Detection Heuristics**
- Search for `safeTransferFrom` followed immediately by `balance += amount` or any form of accounting that uses the passed-in amount rather than a balance delta
- Find contracts that receive tokens from one source and forward the same nominal amount to another address; any fee taken by the source breaks the forwarding assumption
- Check protocol documentation for the list of supported tokens; if it includes any token with a fee switch (USDT), trace all deposit and withdrawal paths for balance-delta handling

**False Positives**
- Protocols that explicitly whitelist only tokens with verified zero-fee implementations and enforce this in the contract's token registration function
- Deposit functions that compute `actualReceived = post_balance - pre_balance` and use that value for all downstream accounting

**Notable Historical Findings**
Y2k Finance's vault did not account for fee-on-transfer mechanics in multiple deposit and withdrawal functions, creating discrepancies between recorded deposits and actual holdings that compounded over time. InsureDAO's vault had the same issue in the premium payment path. Gauntlet's integration found that fee-on-transfer tokens could block entire function families because a withdrawal function assumed the received amount equaled the forwarded amount, causing revert chains when fees were non-zero. A common pattern across all affected protocols was that the code was written assuming standard ERC20 behavior and tested only with compliant tokens.

**Remediation Notes**
- Universally adopt the balance-delta pattern in deposit functions: `uint256 before = token.balanceOf(address(this)); token.safeTransferFrom(...); uint256 actual = token.balanceOf(address(this)) - before;` and use `actual` for all accounting
- In withdrawal paths that receive tokens from external pools, measure the balance before and after the pool withdrawal; forward only the actual received amount, not the requested amount

---

### Front-Running and Sandwich Attacks (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- `finalize()` withdraws all holdings from an AMM pool with no minimum output amounts; an attacker front-runs by manipulating pool composition, then back-runs to profit from the distorted withdrawal
- Pool deposit function does not accept price boundary parameters; attacker can sandwich the deposit, moving the spot price before the trade and reverting it after
- Initial pool deposit (liquidity seeding) is a separate transaction from pool creation; an attacker who sees the creation can front-run the seed deposit and capture the favorable initial price
- Claims or fraud proof submissions are observable in the mempool and can be front-run by the challenged party to nullify the claim before it is processed

**Detection Heuristics**
- Search for pool withdrawal functions (`exitPool`, `returnFunds`, `removeAllLiquidity`) that do not accept `minAmountsOut[]` parameters
- Find deposit functions with no `maxPricesIn[]` or `minSpotPrice` / `maxSpotPrice` guard
- Check initial liquidity seeding transactions; if pool creation and seeding are separate calls, the seeding step is front-runnable
- Look for `block.timestamp` comparisons in time-triggered operations (claim deadlines, fraud proof windows) that are observable before execution

**False Positives**
- Protocols that disable pool swaps before executing large withdrawals (e.g., `setSwapEnabled(false)` before `exitPool`)
- Functions submitted via Flashbots private relays as documented protocol procedure
- Atomic deployment-and-seed operations that leave no window between pool creation and initial liquidity

**Notable Historical Findings**
Gauntlet's managed Balancer vault had both a front-runnable `finalize()` that withdrew all holdings without minimum output protection, and a deposit function susceptible to sandwich attacks that shifted the token composition at the depositor's expense. InsureDAO's initial pool deposit was exploitable because pool creation and the first liquidity deposit were separate transactions; an attacker who observed the creation could front-run the seed to steal initial LP tokens at the deployer's expense. Thesis/tBTC had multiple state transitions (fraud proofs, relay entry timeouts) that created race conditions where multiple parties competed to be the first reporter, and the fraud proof reporter was not bound to the transaction that triggered it. Bridge Mutual's withdrawal queue `RequestPrice` could be front-run in the event of a default, allowing well-positioned actors to exit before the price impact of the default was reflected.

**Remediation Notes**
- All pool withdrawal functions must accept a `minAmountsOut[]` parameter; compute reasonable minimums off-chain and supply them in every call
- Disable pool swaps (`setSwapEnabled(false)`) atomically before withdrawing liquidity; re-enable after, or keep disabled if the vault is winding down
- Combine pool creation and initial liquidity seeding into a single factory transaction to eliminate the front-runnable seeding window

---

### Unbounded Loops and Gas Exhaustion (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Compensation or payout function iterates over all registered insurance indexes or claimants in a single transaction; as the index list grows through normal operation, the function approaches and eventually exceeds the block gas limit
- Queue removal shifts all subsequent array elements left in an O(n) operation; a queue with many entries can make removal prohibitively expensive or cause it to revert
- Staking delegation maps track an unbounded array of delegators per service provider; reward distribution iterates this array, enabling a griefing attack through cheap micro-delegations
- Withdrawal queue processing iterates all pending entries up to available liquidity without a per-transaction batch limit

**Detection Heuristics**
- Search for `for (uint256 i = 0; i < array.length; i++)` in storage arrays with no hard upper bound on array length
- Find array removal operations that use element-shifting (copying `array[i] = array[i+1]` in a loop); estimate gas for worst-case array sizes
- Identify delegation or staking functions with no minimum amount requirement; trace where the resulting array is later iterated
- For withdrawal queue processing, check whether a `maxIterations` or `batchSize` parameter limits per-transaction work

**False Positives**
- Arrays with a hard-cap enforced at insertion time (e.g., `require(indexList.length < MAX_INDEXES)`)
- Protocols deployed on high-gas-limit L2 chains where the practical risk of gas exhaustion is orders of magnitude lower
- Operations restricted to trusted administrators whose incentive alignment prevents deliberate inflation

**Notable Historical Findings**
InsureDAO's `compensate()` function iterated every registered index twice per call to compute shares; as the protocol onboarded more indexes, this function crept toward the block gas limit and would eventually become permanently uncallable. Bridge Mutual's queue removal function shifted all elements after the removed index, making removal of early-queue entries O(n) in queue length; combined with the `_updateWithdrawalQueue` function iterating all pending entries, a filled queue could exceed block gas limits. Audius's delegation contract allowed zero-amount delegations, enabling a malicious delegator to fill the delegators array at near-zero cost and subsequently prevent all other delegators from delegating or claiming rewards.

**Remediation Notes**
- Replace unbounded storage arrays with linked-list structures or pagination-supporting index mappings; expose a `process(startIndex, batchSize)` pattern for any function that must iterate many entries
- For queue removal, use a linked-list (`head`, `tail` pointers with a `next` mapping) to achieve O(1) removal instead of O(n) shifting
- Enforce a minimum stake or delegation amount that makes spam economically infeasible; `require(amount >= MIN_DELEGATION)` in every entry-point function

---

### Withdrawal Queue Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Cancellation of a queue entry sets a `pendingCancelRedeemRequest` flag but does not advance the `nextRequestId` pointer; when the cancelled entry is encountered during processing, the loop reaches a zero-shares entry and breaks, deadlocking the queue permanently
- Array-based queue uses a `length` field that is decremented on removal but the last element is not popped, leaving a ghost entry that consumes a slot and is iterable but logically absent
- Multiple fulfillment paths (manual, instant, batch) each independently verify available liquidity against `totalAssets()` without subtracting a shared `reservedLiquidity` counter, allowing overlapping reservations that the vault cannot honor
- Partial redemption fulfillment updates `claimableAssets` correctly but does not decrement the request's `shares` to match, causing `fulfillCancelRedeemRequest` to compute a mismatched delta on the stale share count

**Detection Heuristics**
- Trace all operations that modify `nextRequestId`: confirm that cancellation, timeout, and zero-share skipping all advance this pointer rather than breaking out of the processing loop
- In queue removal functions, verify the final element is explicitly `pop()`d or that the length field is decremented atomically with the element removal
- Find all locations that check liquidity before fulfilling a redemption; confirm a shared `reservedLiquidity` variable is decremented at claim time and incremented at reservation time, preventing double-booking
- Cross-check `fulfillRedeemRequest` and `fulfillCancelRedeemRequest`: verify that both operate on the same version of the request's `shares` and `claimableAssets` fields

**False Positives**
- Queue implementations using a mapping with head/tail pointers rather than a sequential array; these avoid most shifting and stale-entry issues
- Protocols with an off-chain operator responsible for queue processing where the operator's incentives and capabilities prevent queue abandonment
- Cancellations that are synchronous and immediately clean up all queue state in one transaction

**Notable Historical Findings**
Accountable Protocol had at least five distinct withdrawal queue vulnerabilities reported in a single audit: cancelling a redeem request permanently blocked the withdrawal queue by leaving `nextRequestId` pointed at a zero-shares entry that the processing loop could not advance past; partial redemptions could be exploited to steal assets by re-processing a request whose shares had not been decremented; the queue amount variable was used inconsistently between queuing and dequeueing operations; manual and instant fulfillment paths did not reserve liquidity, enabling concurrent fulfillments to over-commit the vault's holdings; and `fulfillCancelRedeemRequest` used stale share data causing a state desync. Bridge Mutual had three separate queue bugs: the remove function did not fully remove items (missing pop), `_updateWithdrawalQueue` could exhaust block gas on large queues, and an inconsistent `aggregatedQueueAmount` tracking variable caused accounting drift.

**Remediation Notes**
- Cancellation must advance `nextRequestId` past all cancelled (zero-shares) entries before returning; implement a `while (nextRequestId < lastRequestId && requests[nextRequestId].shares == 0) { nextRequestId++; }` cleanup loop in the cancellation function
- All fulfillment paths must use a single shared `reservedLiquidity` variable; check `require(assets <= totalAssets() - reservedLiquidity)` and then increment `reservedLiquidity += assets` atomically before updating the request state
- Bound queue processing loops with a `maxIterations` parameter to prevent gas exhaustion; persist the `nextRequestId` after each bounded run so processing can resume in subsequent transactions

---

### Oracle Price Feed Misconfiguration (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Insurance protocol deployed on Arbitrum or Optimism uses Chainlink price feeds without checking the sequencer uptime feed; during a sequencer outage, stale prices can trigger incorrect depeg events or prevent legitimate claims
- `PegOracle` combines two Chainlink feeds of different decimal precisions using a hardcoded `10000` multiplier; the resulting ratio is incorrect by a factor of `10^(decimals_delta)`, causing the depeg threshold to be hit at the wrong price
- Oracle timeout returns `(0, FIX_MAX)` rather than reverting; downstream logic interprets the zero as a valid price and executes a sell-off of the protocol's RSR or collateral at near-zero
- Risk users are required to pay out if the pegged asset's price goes higher than the peg, which is the inverse of the intended trigger condition, due to inverted comparison logic in the depeg check

**Detection Heuristics**
- Search for `latestRoundData()` calls; verify `answeredInRound >= roundId`, `price > 0`, `updatedAt > 0`, and `block.timestamp - updatedAt < maxStaleness`
- For protocols on L2, verify a sequencer uptime feed is consulted and a grace period (typically one hour) is enforced after sequencer restart before price consumption resumes
- Find oracle timeout handling; trace whether it returns a zero, a sentinel, or reverts; if it returns a zero, find all downstream uses and verify they treat zero as invalid
- In depeg oracle comparisons, verify the inequality direction: a USD-pegged asset depegs when its price falls below `$1 - threshold`, not above it

**False Positives**
- L1 Ethereum deployments where sequencer uptime is irrelevant
- Oracle aggregator contracts that centralize all staleness, sequencer, and decimal checks before exposing a validated price to the protocol
- TWAP-based parametric triggers where staleness is inherently bounded by the TWAP window

**Notable Historical Findings**
Y2k Finance had a cluster of oracle bugs: incorrect `pricefeed.decimals()` handling in `PegOracle` produced an off-by-factor-of-scale ratio; the depeg trigger fired when the asset went above peg rather than below it, requiring risk users to pay out in the wrong scenario; the oracle combination function had a loss-of-precision path that output the wrong price ratio; and a stale price timeout path caused `endEpoch` to be uncallable, permanently trapping winner funds. Bond Protocol on Arbitrum did not check the sequencer uptime feed, exposing covered positions to stale price settlement during sequencer outages. Reserve Protocol's `Asset.lotPrice()` used an incorrect price during oracle timeout, not the most recent valid price, leading to below-market auction settlement.

**Remediation Notes**
- Implement a single `getValidatedPrice(AggregatorV3Interface feed)` function used by all price consumers: check sequencer uptime (L2 only), validate all five `latestRoundData` fields, normalize to 18 decimals using `feed.decimals()`, and revert with a named error on any validation failure
- Replace oracle timeout return values of `(0, FIX_MAX)` with a revert or a transition to a `PAUSED` state; never allow a zero price to flow into settlement or auction logic
- When combining two oracle feeds in a ratio, compute decimals dynamically: `uint256 price1Normalized = price1 * 10**(18 - feed1.decimals())` before dividing
