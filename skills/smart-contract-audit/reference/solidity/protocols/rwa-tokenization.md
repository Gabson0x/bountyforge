# Real World Asset Tokenization Security Patterns

> Applies to: tokenized real world assets, tokenized treasuries, tokenized real estate, tokenized securities, permissioned ERC-20 tokens, KYC-gated tokens, Centrifuge-style, Ondo-style, off-chain asset backing

## Protocol Context

Real world asset tokenization protocols bridge off-chain assets - treasuries, real estate, private credit - onto a blockchain as permissioned tokens backed by off-chain legal structures. The security model diverges from pure DeFi protocols in that it depends on correct enforcement of KYC/AML restrictions, oracle-reported NAV values, and administrative key management for the custodial bridge. Token transfer restrictions must hold across every balance-changing operation including mint, burn, transfer, ERC4626 deposit/redeem, and cross-chain bridge operations; a single unchecked code path bypasses the compliance layer entirely.

The off-chain backing introduces oracle trust assumptions that differ from price-feed oracles: NAV values are reported by authorized administrators rather than decentralized feeds, creating a privileged role that can misrepresent asset value. Smart contract risk is therefore dominated by access control correctness, restriction bypass through approval-based token transfers, and the interaction of permissioned token semantics with standard DeFi primitives that were not designed with transfer restrictions in mind.

## Bug Classes

---

### Access Control Bypass (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Privileged functions - deposit, claim, mint, propose, execute - use a user-supplied address parameter (receiver, beneficiary, collateral holder) for validation rather than `msg.sender`. Alternative public entry points exist that internally invoke access-controlled logic without re-applying the guard. Role-based modifiers are missing on at least one critical state-changing function. Protocols with KYC-gated tokens often validate the token recipient instead of the caller, creating a systematic bypass surface.

**Detection Heuristics**
Enumerate all external and public functions that modify balances, loans, reward state, or governance. Check that `msg.sender` is compared directly to the authorized party - not to a function-argument address. Trace all internal functions that touch restricted logic and verify every entry point applies the same guard. Look for `depositReward`-style functions callable with zero amounts that still reset `periodFinish` or `rewardRate` without any role check.

**False Positives**
Functions intentionally permissionless by design (e.g., anyone may trigger liquidation of an undercollateralized position). Cases where receiver-address validation is sufficient because only the holder economically benefits. Functions protected by a proxy-layer access control that does not appear in the implementation contract.

**Notable Historical Findings**
In Astaria, `commitToLien` validated the collateral holder's address as the receiver rather than verifying the caller, allowing any party to open a loan against another user's NFT collateral without consent. Separately, a missing `onlyOwner` check on `depositReward` in Zivoe allowed anyone to call the function with a zero reward amount, extending `periodFinish` and diluting the reward rate for existing stakers at no cost. In Ondo Finance, `KYCRegistry` was susceptible to signature replay, and `setPendingRedemptionBalance` could cause a user's cash token to be silently lost through an unchecked state transition.

**Remediation Notes**
Validate `msg.sender` directly against the owner, approved operator, or authorized role - never a caller-supplied address. On reward distribution functions, enforce a role guard and a non-zero reward amount check together. Apply modifiers consistently to every overload and internal entry point, not only to the canonical external function. For KYC-gated protocols, decouple identity verification from the operation's authorization check.

---

### Blacklist and Pause Mechanism DoS (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Protocol integrates with USDC, USDT, or a permissioned RWA token whose issuer maintains a blocklist or pause switch. A critical operation - liquidation, withdrawal settlement, reward claim - iterates over user addresses and must push tokens to each one. A single blacklisted or sanctioned address in the loop causes the entire transaction to revert. Protocols built for regulated markets are disproportionately affected because compliance-driven blocking is expected behavior, not an edge case.

**Detection Heuristics**
Identify every loop that transfers tokens to addresses derived from user-supplied or protocol-maintained lists. Confirm whether the token in scope has a pause or blacklist function at the contract or issuer level. Check whether liquidation and auction settlement paths have try/catch wrappers or skip-and-escrow logic. Look for admin-controlled operations that require all users to have exited before the admin can proceed (e.g., `withdrawExcessRewards` guarded by `totalUsersDeposited == 0`).

**False Positives**
Tokens guaranteed to lack blocklist or pause mechanisms (WETH, DAI). Loops that wrap each transfer in try/catch and credit to an escrow mapping on failure. Protocols with admin override paths that can force-complete operations regardless of individual transfer results.

**Notable Historical Findings**
In Opyn Crab Netting, the `netAtPrice` function iterated a withdrawal queue and pushed USDC to each address; a single USDC-blacklisted user permanently froze the netting and withdraw auction. In the Shiny protocol, a paused or blacklisted RWA NFT contract caused `liquidate` to revert because the burn call was mandatory and had no fallback. In Derby, blacklisting a DeFi protocol within the yield router silently lowered vault allocations rather than triggering a safe fallback, while an emergency blacklist operation could itself revert under certain conditions.

**Remediation Notes**
Replace push-payment patterns with pull-payment (credit-then-claim) for any function that must iterate over user addresses. Decouple liquidation finality from the success of external token transfers by routing proceeds to an escrow contract on failure. Where possible, design permissioned-token interactions to be retryable after a user is removed from a blocklist rather than treating the blocked state as permanent.

---

### Cross-Chain Bridge Vulnerabilities (ref: no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
Protocol bridges tokenized assets or messages across chains using Optimism-style withdrawal flows, Axelar's interchain gateway, or a custom bridge. Gas buffer calculations for withdrawal finalization do not account for all intermediate opcodes between the check and the external call. Cross-chain message receivers validate only that `msg.sender` is the bridge contract, without verifying the origin-chain sender address. Token decimal representations differ between chains and are not normalized during bridging. Failed cross-chain operations have no replay mechanism, permanently stranding funds.

**Detection Heuristics**
Audit the gas buffer constant in withdrawal finalization: count every storage access and external call between the `gasleft()` check and the actual forwarded call, then verify the buffer exceeds this overhead by at least 10,000 gas. In `xReceive`-style handlers, confirm both `msg.sender == bridge` and `_originSender == authorizedSenders[_origin]` are checked. Compare token decimals between each supported chain pair. Verify that finalization functions do not mark the withdrawal hash as complete before the call succeeds.

**False Positives**
Gas buffers large enough to cover all intermediate operations without developer action. Origin sender verified against a contract-level whitelist mapping. Protocols deployed only on chains where the bridged token shares the same decimal precision. Bridge deployments where failed messages can be replayed via the canonical messenger.

**Notable Historical Findings**
Multiple Optimism audits identified that `finalizeWithdrawalTransaction` consumed approximately 5,000 gas between its gas check and the forwarded call, allowing an attacker to supply exactly enough gas to pass the check while the actual call received less than the declared `gasLimit`, permanently locking funds with no replay path. In Axelar's interchain token service, bridge requests to chains where the token was not yet deployed caused a DoS without automatic recovery. Derby's cross-chain provider used an incorrect `chainId` comparison and also allowed an attacker to spoof cross-chain vault rebalancing messages because the origin sender was not authenticated.

**Remediation Notes**
Perform all state mutations before the gas check; place the check immediately before the external call with a buffer that accounts for the full measured opcode cost. Authenticate both the bridge contract (`msg.sender`) and the origin-chain sender address in every cross-chain message receiver. Normalize token amounts to the destination chain's decimal precision before forwarding. Allow finalization to be retried on failure by setting the finalization flag only after a successful call.

---

### Denial of Service via Unbounded Operations (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Contract maintains user-controlled arrays - delegation lists, deposit queues, withdrawal queues - that grow without a meaningful economic cost gate. Iteration over these arrays occurs within a single transaction during settlement, reward distribution, or epoch processing. An attacker can inflate the array at negligible cost (dust deposits, 1-wei delegations), causing legitimate operations to exhaust the block gas limit. Soft caps (e.g., `MAX_DELEGATES = 1024`) are too high to prevent griefing when the minimum value per entry is 1 wei.

**Detection Heuristics**
Find all loops iterating over storage arrays and check whether the array length is bounded by a hard economic constraint. Verify that cancelled, zero-value, or processed entries are pruned and not iterated over in perpetuity. Calculate the gas cost at the array's theoretical maximum size and compare to the block gas limit. For delegation patterns, compute the minimum cost to fill the array to its cap and compare to the expected damage.

**False Positives**
Arrays backed by a minimum stake large enough to make filling the cap economically irrational. Paginated processing where partial progress is committed to storage and resumed across transactions. Admin-only insertion where the griefing vector requires the attacker to control a privileged role.

**Notable Historical Findings**
In Alchemix's veALCX, an attacker could delegate tokens from up to 1,024 positions to a single address for near-zero cost, making any on-chain operation that iterated the delegate list prohibitively expensive. Opyn Crab Netting was vulnerable to the same pattern in both deposit and withdrawal queues: an attacker queuing thousands of tiny deposits then cancelling them still forced the protocol to iterate every cancelled entry on the next processing call. FactoryDAO's `withdrawExcessRewards` became permanently unexecutable when an attacker queued enough small deposits to push the iteration gas above the block limit.

**Remediation Notes**
Enforce a minimum economic value per array entry that makes griefing costlier than the damage caused. Implement paginated processing functions that accept start and stop indices and commit progress between calls. Clean up or compact arrays as entries are processed rather than relying on skip-empty logic. Set maximum array sizes low enough that the gas cost at the cap fits comfortably within the block gas limit.

---

### First Depositor Share Inflation Attack (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Vault or staking pool uses share-based accounting (ERC-4626 or equivalent). No minimum initial deposit, no dead shares mechanism, and no virtual offset is applied to `totalAssets()` or `totalSupply()`. A first depositor can obtain shares with a 1-wei deposit and then donate underlying tokens directly to the vault contract to inflate the exchange rate before any second depositor arrives. Share calculations use integer division that rounds down, causing a second depositor's share count to round to zero when the donation is large relative to their deposit.

**Detection Heuristics**
Check if the share calculation is `(assets * totalSupply) / totalAssets()` with no virtual offset and no revert-on-zero-shares guard. Verify whether `totalAssets()` accounts for direct token donations or only tracks internally recorded deposits. Look for absence of dead shares minted to `address(0)` or a burn address at vault initialization. For reward multiplier schemes, check whether `POINTS_MULTIPLIER` scaled by a 1-share supply can cause arithmetic overflow in correction accounting.

**False Positives**
Vaults using the OpenZeppelin ERC-4626 virtual offset (`_decimalsOffset`). Vaults that mint dead shares equal to a `MINIMUM_LIQUIDITY` constant on the first deposit. Vaults where `totalAssets()` is purely internal accounting, unaffected by direct token transfers.

**Notable Historical Findings**
In Rubicon's compound fork, a first depositor minted 1 share for 1 wei and donated enough underlying tokens to the vault to make every subsequent depositor's share calculation round to zero, effectively stealing all subsequent deposits. Merit Circle's staking pool used a large `POINTS_MULTIPLIER` constant; with a 1-share total supply, a normal deposit amount caused `_correctPoints` to compute a value that overflowed `int256`, making the contract permanently unusable. Ondo Finance and Astaria both reported variants where the first vault deposit established an exchange rate that over-penalized subsequent depositors through rounding.

**Remediation Notes**
Apply a virtual shares and virtual assets offset (OpenZeppelin's `_decimalsOffset`) or lock a `MINIMUM_LIQUIDITY` amount to a dead address on the first deposit. Revert explicitly when a deposit would produce zero shares. Do not allow `totalAssets()` to reflect tokens transferred directly to the contract address outside the deposit function.

---

### Frontrunning and MEV Exploitation (ref: fv-sol-8)

**Protocol-Specific Preconditions**
Reward distribution, exchange rate updates, or epoch-boundary bribe settlements are observable in the public mempool before confirmation. No snapshot-based accounting, minimum staking duration, or commit-reveal prevents a party from depositing immediately before a favorable event and withdrawing immediately after. Governance functions reference the currently active proposal implicitly, so a proposal swap between submission and mining redirects votes. Swap operations compute slippage bounds from the same pool being manipulated.

**Detection Heuristics**
Identify reward `distribute()` functions where the reward amount is readable from pending mempool transactions and no snapshot guards deposits made after the last epoch boundary. Check exchange-rate-updating functions (e.g., `repayBorrow` or `checkpoint`) for patterns where a deposit immediately before and a redemption immediately after extract the rate delta as risk-free profit. Audit epoch-boundary vote and bribe mechanics for the ability to reset votes after earning bribe credit without contributing to the new epoch. Look for governance vote functions that read the active proposal from state rather than accepting an explicit proposal ID parameter.

**False Positives**
Protocols using ERC-20 snapshot extensions where reward eligibility is determined at a snapshot taken before the distribution transaction. Protocols operating on chains with private ordering or where MEV extraction requires infrastructure unavailable on that network. Swap functions where the minimum output is supplied by the caller via calldata from an off-chain quote.

**Notable Historical Findings**
In Alchemix's veALCX, attackers could front-run `distribute()` by depositing into a gauge right before new emissions arrived and back-running by withdrawing, capturing a full epoch's rewards for zero lock-up time. The same protocol's bribe mechanism allowed a voter to reset votes at the epoch boundary after establishing bribe eligibility in the previous epoch, claiming bribes for a period they did not contribute to. In Union Finance, the `repayBorrow` path increased `totalRedeemable`, which raised the `exchangeRateStored`, enabling a sandwich where an attacker minted UTokens at the old rate and redeemed them at the new rate for a risk-free spread.

**Remediation Notes**
Use snapshot-based reward accounting where eligibility is determined at the previous epoch boundary and fresh deposits during the current epoch are ineligible. Enforce a minimum staking duration before reward claims. Require governance vote functions to accept an explicit proposal ID parameter and validate it against the active proposal. Derive slippage bounds from off-chain sources and pass them as calldata parameters rather than computing them on-chain in the same transaction as the swap.

---

### Funds Permanently Locked or Frozen (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol holds user funds subject to conditional withdrawal logic (epoch finalization, auction settlement, cross-chain message delivery). The withdrawal path depends on at least one external call that can permanently fail (pausable token, blacklisted address, dead contract). State transitions can become stuck when their preconditions depend on external actions that may never complete (e.g., outstanding liens, unresolved auctions). No admin emergency recovery path exists. Token merge and burn operations destroy a position without first extracting all accrued value.

**Detection Heuristics**
Trace every path where user funds enter the contract and verify a corresponding exit path for all failure scenarios including zero-bid auctions, paused tokens, and cross-chain delivery failures. Check epoch processing functions for hard `require` conditions that depend on external state (e.g., `liensOpenForEpoch == 0`). Verify that cross-chain finalization marks the hash as complete only after a successful call, not before. For any merge or burn operation, confirm all pending rewards and claimable value are extracted atomically before the position is destroyed.

**False Positives**
Protocols with explicit admin emergency withdrawal functions covering all stuck-fund scenarios. Stuck amounts bounded to sub-wei dust by design. Protocols that explicitly and transparently forfeit unclaimed funds after a documented grace period.

**Notable Historical Findings**
Astaria's `processEpoch` required `liensOpenForEpoch == 0` before advancing, so a single expired lien that could not be liquidated (e.g., due to a paused NFT contract) halted all withdrawal requests for an epoch indefinitely. Alchemix's veALCX destroyed unclaimed ALCX rewards permanently when merging two positions because neither a pre-merge claim step nor a post-merge recovery path existed. Zivoe's `depositReward` with a zero-amount call erroneously locked reward tokens inside the contract with no retrieval mechanism.

**Remediation Notes**
Implement a force-close or admin-bypass path for every protocol state that can block epoch processing. Mark cross-chain withdrawal hashes as complete only after the external call succeeds and allow retry on failure. Make merge and burn operations atomic with a reward claim. Provide an explicit admin emergency withdrawal function that can operate independently of normal accounting invariants.

---

### Liquidation Mechanism Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Lending or lien-based protocol computes debt for the liquidation trigger using a different formula (without discount) than the internal debt update function uses (with discount). Liquidation does not atomically mark the position as liquidated, allowing re-entry or repeated calls. The auction settlement path is separate from the liquidation trigger, and the no-bid case leaves lien accounting in a corrupt state. External dependencies (NFT burn, oracle read, Seaport order validation) can silently fail or revert within the liquidation path.

**Detection Heuristics**
Compare the debt value passed to the liquidation function with the value that will be used in the internal `updateDebt` modifier - verify they both include or both exclude the same discounts and accrued interest. Confirm that the liquidation function sets an `isLiquidated` flag before creating an auction. Check the no-bid auction settlement path for uncleaned lien data, uncorrected public vault accounting, and unupdated slope/yIntercept values. Verify that any call to an external contract within the liquidation path is wrapped in try/catch or that its failure cannot permanently block the position.

**False Positives**
Protocols where the discount profile is always zero (`NoDiscountProfile`) and no other profiles are deployed. Protocols intentionally supporting partial liquidations where multiple calls to the same position are expected. External call failures caught and handled gracefully by the protocol's existing architecture.

**Notable Historical Findings**
In Mochi, `triggerLiquidation` passed the raw debt without discount to the vault's liquidation function while the vault's internal update applied a discount; the difference caused an underflow whenever the discount was non-zero, making liquidation completely non-functional. Astaria produced multiple related findings: `liquidate` could be called repeatedly on the same expired lien creating duplicate Seaport auctions; when an auction ended with no bids, `liquidatorNFTClaim` failed to clean lien data and update the public vault's accounting, leaving phantom liens and incorrect slope values on the books.

**Remediation Notes**
Use a single canonical debt calculation function with consistent discount and interest-accrual logic for all external and internal callers. Set the `isLiquidated` flag before creating any external auction. Implement a unified settlement function for the no-bid case that clears all lien state and corrects public vault accounting. Wrap external calls in the liquidation path in try/catch and provide an admin recovery path for stuck positions.

---

### Non-Standard ERC-20 Token Handling (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Protocol accepts user-specified token addresses or maintains a whitelist that could include fee-on-transfer tokens, rebasing tokens, ERC-777 tokens with transfer hooks, or USDT-style tokens that require allowance to be zeroed before being set. The contract uses the transferred `amount` parameter directly in accounting without measuring the actual balance change. USDT's `approve` reverts when called with a non-zero current allowance and a non-zero new allowance.

**Detection Heuristics**
Search for `transferFrom` calls where `amount` is used in accounting without a before/after `balanceOf` check. Look for `approve` calls not preceded by a zero-approval reset when the token could be USDT. Check for reentrancy guards on functions that transfer tokens to user-controlled addresses and could be re-entered via ERC-777 hooks. Verify that zero-value transfers do not revert for all tokens in scope. For rebasing tokens, assess whether internal accounting diverges from actual balances over time.

**False Positives**
Protocols explicitly restricted to a whitelist of known standard tokens (WETH, canonical stablecoins) with no upgrade path that could introduce non-standard behavior. Protocols already using the balance-before/after measurement pattern. `safeTransfer` usage from OpenZeppelin (handles non-returning tokens but does not handle fee-on-transfer - this distinction matters).

**Notable Historical Findings**
In Axelar's interchain token service, fee-on-transfer tokens produced accounting discrepancies because the protocol recorded the transferred amount rather than the received amount, allowing cumulative drain of other users' balances. In Astaria, USDT approval calls without prior zero-reset caused Seaport auction settlements to revert for USDT vaults. Axelar's flow limit logic for ERC-777 tokens was broken because the callback path allowed re-entry that bypassed the limit counter update.

**Remediation Notes**
Use the balance-before/after pattern (`balanceAfter - balanceBefore`) for all tokens admitted by a user-specified or extensible whitelist. Reset allowance to zero before granting a new non-zero allowance. Apply `nonReentrant` to all functions that transfer tokens to user-controlled addresses. Document explicitly which token types are supported and enforce this at the whitelist registration step.

---

### Oracle and Price Manipulation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol prices collateral using AMM spot reserves, LP token `getRate()`, or Uniswap `slot0()` without a TWAP or Chainlink cross-check. LP token pricing applies a formula designed for Curve stable pools to Balancer weighted pools or vice versa, producing systematic overvaluation. Flash loans allow an attacker to temporarily distort pool ratios in the same transaction as the protocol's price read. Chainlink staleness checks (`updatedAt` validation) are absent or use inconsistent thresholds across different price feeds in the same calculation.

**Detection Heuristics**
Enumerate all `getReserves()`, `getRate()`, `slot0()`, and `baseAmount()` calls and trace whether their output is used in collateral valuation, liquidation thresholds, or value transfers. Confirm the LP pricing formula matches the pool type: Curve virtual price for stable pools, fair-value geometric mean formula for weighted pools. Look for absence of `updatedAt` staleness checks on Chainlink feeds and inconsistency in staleness thresholds between feeds combined in the same calculation. Check if the price read and the collateral-using operation can occur in the same transaction, enabling flash loan manipulation.

**False Positives**
Chainlink oracles with proper staleness checks used as the primary and sole price source. TWAP with a window long enough (at minimum 30 minutes) to make flash loan manipulation economically infeasible. LP prices derived from a manipulation-resistant virtual price (Curve `get_virtual_price` with a reentrancy lock).

**Notable Historical Findings**
In Blueberry Update #3, the `WeightedBPTOracle` applied Curve's `minPrice * getRate()` formula to Balancer weighted pools, overvaluing LP tokens by roughly 12% and enabling protocol insolvency through over-leveraged positions. Spartan Protocol's `realise` function calculated synth value directly from AMM spot reserves; a flash loan could skew the pool ratio enough to extract protocol value through a single atomic transaction. Zivoe's `OCL_ZVE.forwardYield` read directly from manipulable Uniswap V2 pool reserves for yield routing decisions.

**Remediation Notes**
Use Chainlink as the primary price source with staleness validation and a maximum deviation circuit breaker against on-chain prices. For LP tokens, implement the fair-value pricing formula appropriate to the pool type rather than reusing a formula from a different pool architecture. Add a reentrancy lock before reading Curve `get_virtual_price` to prevent read-only reentrancy manipulation. Never use the same transaction's pool state as both the manipulation vector and the price input.

---

### Precision Loss and Rounding Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Contract mixes token amounts with different decimal precisions (6, 8, 18) in the same arithmetic expression. Division is performed before multiplication, producing a zero intermediate result for amounts smaller than the divisor. WAD-scaled values (1e18) are passed to `mulWadDown` or similar functions alongside token amounts denominated in a non-18-decimal token. Unsafe downcasting from `uint256` truncates high bits for values that exceed the target type's range. Reward-per-share calculations using a large precision multiplier (`type(uint128).max`) overflow when multiplied by normal deposit amounts.

**Detection Heuristics**
Search for expressions where a division result is subsequently multiplied: the intermediate value may round to zero for small inputs. Verify that every `mulWadDown` / `divWadDown` call operates on values where both operands are in WAD scale; non-18-decimal token amounts must be normalized first. Flag all explicit casts to narrower integer types (`uint48`, `uint96`, `uint128`) and verify bounds proofs. In reward distribution contracts, calculate the maximum value that `pointsPerShare * shares` can reach and compare to `type(int256).max`.

**False Positives**
Precision loss bounded to sub-wei amounts per user by design. Division-before-multiplication that is intentional for gas optimization with provably bounded inputs where the intermediate cannot be zero. Downcasts that are safe because the value is provably within range by a preceding check.

**Notable Historical Findings**
Opyn Crab Netting's `withdrawAuction` performed `(withdraw.amount * 1e18 / crabToWithdraw) * usdcReceived / 1e18`; when `withdraw.amount` was smaller than `crabToWithdraw` the first intermediate rounded to zero, producing a zero USDC payout for the user. Astaria's `claim()` function used `10**ERC20(asset()).decimals() - s.withdrawRatio` where USDC has 6 decimals but `withdrawRatio` is WAD-scaled, causing consistent underflow for any non-18-decimal vault asset. Alchemix reported multiple HIGH-severity findings where `getClaimableFlux` miscalculated flux rewards due to a double application of multipliers and incorrect use of WAD scaling, collectively preventing a significant fraction of users from claiming correct reward amounts.

**Remediation Notes**
Always multiply before dividing when computing share-of-total ratios. Normalize token amounts to a common precision before performing WAD arithmetic. Use OpenZeppelin `SafeCast` for all explicit downcasts. For reward multiplier schemes, bound `POINTS_MULTIPLIER` to a value that cannot overflow `int256` when multiplied by the maximum expected user balance.

---

### Reward and Yield Distribution Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Distribution function is called before the state update that feeds it (e.g., `distribute()` runs before `updatePeriod()` sends new emissions), causing zero-balance distributions. `checkpoint()` reads `balanceOf(address(this))` and treats the entire balance as new revenue, re-counting unclaimed amounts from prior checkpoints. Merge, burn, or transfer operations destroy a veToken or staking position without first claiming accrued rewards for that position. Reward-per-token calculations do not handle the `totalSupply == 0` case, causing rewards deposited during zero-staker periods to be permanently lost or incorrectly allocated.

**Detection Heuristics**
For any `distribute()` or `notifyRewardAmount()` call, confirm that upstream emission logic (minter, yield aggregator) has already settled the new reward amount before distribution uses it. In `checkpoint()` or `revenueHandler` patterns, verify that only newly arrived tokens since the last checkpoint are counted as new revenue. For every merge, burn, or transfer of staked positions, verify all pending rewards are claimed atomically in the same transaction. Check `rewardPerToken()` for a zero-supply guard that correctly defers rather than discards rewards.

**False Positives**
Reward loss bounded to sub-wei rounding. Ordering dependency enforced by an external keeper that always executes the correct sequence in a single multicall. Protocol explicitly and transparently forfeits rewards deposited during zero-staker periods.

**Notable Historical Findings**
Alchemix's veALCX is the densest historical source for this bug class: distribute was called before `updatePeriod` causing zero-emission periods, unclaimed revenue was re-counted on each checkpoint causing protocol insolvency, killed gauges continued accumulating and extracting from the minter, users who merged positions lost all pending ALCX rewards because no pre-merge claim was enforced, and the `checkpointTotalSupply` function could checkpoint before a timestamp was complete, producing incorrect historical supply data. Derby's vault incorrectly shared reward pools between stakers and game players and allowed players to call rebalance before rewards had been pushed to the game contract.

**Remediation Notes**
Always trigger upstream emission settlement before reading the reward balance in `distribute`. Measure newly received rewards as the delta between the current balance and a stored `lastBalance` variable, not as the raw current balance. Make merge and burn operations atomic with a `_claim` call for the source position. Implement a zero-supply guard in `rewardPerToken` that preserves rewards for the first staker rather than silently discarding them.

---

### Missing Slippage Protection in Token Swaps (ref: fv-sol-8)

**Protocol-Specific Preconditions**
Contract executes on-chain token swaps during reward claims, rebalances, or vault checkpoints where the `amountOutMinimum` is either zero, hardcoded to the input amount, or derived from a quoter call in the same transaction against the same pool being swapped. No off-chain quote or Chainlink price floor is used to establish a minimum acceptable output. The swap function is callable by external users or triggered automatically without user-supplied slippage bounds.

**Detection Heuristics**
Audit every external DEX router call (`exactInput`, `exactInputSingle`, `exchange`, `swap`) for the minimum output parameter. Check whether the parameter is zero, equals the input amount (wrong assumption for non-pegged pairs), or is computed on-chain using `IQuoter` against the pool that will be immediately swapped. Look for `deadline: block.timestamp` and `deadline: type(uint256).max` which provide no meaningful protection. Identify reward claim, rebalance, and yield forwarding flows that trigger swaps without exposing a caller-supplied minimum.

**False Positives**
Swaps occurring within a flash loan callback that atomically validates the final output against an invariant. Off-chain keepers that pass externally computed `minAmountOut` values as calldata parameters to internal-only functions. Stablecoin-to-stablecoin swaps with negligible price deviation relative to fees. Dust-level swap amounts where sandwich attacks are economically unprofitable.

**Notable Historical Findings**
Derby's vault executed Uniswap swaps with `amountOutMinimum = 0` during rebalancing, reported twice across two separate audit rounds. Alchemix's `RevenueHandler` performed token swaps with an incorrect minimum output calculated assuming a 1:1 token price; the function also used an on-chain quoter for the same pool being swapped, making the minimum output trivially bypassable in the same transaction. Blueberry Update #3's Aura spell exited a pool during position closure without slippage protection, exposing the full withdrawal to sandwich attacks.

**Remediation Notes**
Require a caller-supplied `minAmountOut` parameter on all swap-executing functions and validate it is non-zero. Use an off-chain quote or a Chainlink oracle as the price floor rather than an on-chain quoter from the same pool. Set deadlines to a meaningful timestamp (e.g., `block.timestamp + DEADLINE_BUFFER`) supplied by the caller. For protocol-internal automated swaps, route through a trusted aggregator with on-chain price validation.

---

### Unsafe External Calls and Unchecked Return Values (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Contract calls `transfer()` or `transferFrom()` on tokens that return `false` on failure rather than reverting. State is updated before the transfer, or the return value is ignored, causing accounting to reflect a transfer that did not occur. ETH is sent via `payable.transfer()`, which forwards only 2,300 gas and fails for smart contract recipients with non-trivial `receive()` logic (Gnosis Safe, multisig wallets). Low-level `call` succeeds against a target with no code, silently discarding the fee.

**Detection Heuristics**
Grep for `transfer(` and `transferFrom(` calls not immediately wrapped in `require` or an `if (!success)` check. Verify SafeERC20 (`safeTransfer`, `safeTransferFrom`) is used for all ERC-20 interactions. Search for `payable(x).transfer(` patterns and replace with `call{value:}`. In fee distribution paths, verify that the target has code before assuming a `call` succeeded.

**False Positives**
Tokens that always revert on failure (standard OpenZeppelin ERC-20). Protocols that already use SafeERC20 throughout. ETH recipients verified to be EOAs or contracts with known gas-efficient `receive()` functions.

**Notable Historical Findings**
In Spartan Protocol, `iBEP20.transfer` return values were consistently not checked, allowing silent failures across multiple withdrawal and distribution functions. In Escher, an NFT sale contract used `payable.transfer()` for ETH refunds; smart contract buyers whose `receive()` function exceeded 2,300 gas were permanently unable to receive their refund. Rubicon Router used `transfer()` for ETH sends in its router, failing for any caller that was a smart contract wallet.

**Remediation Notes**
Use OpenZeppelin SafeERC20 for all ERC-20 transfers. Replace `payable(x).transfer(amount)` with a low-level `call{value: amount}("")` that checks the return value and handles failure explicitly (restore state or emit a retriable event). Verify the code size of fee recipient addresses if they are set dynamically.
