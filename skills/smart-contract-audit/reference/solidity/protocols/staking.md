# Staking Protocol Security Patterns

> Applies to: staking pools, liquid staking, validator pools, ETH staking, staking derivatives, Lido-style, RocketPool-style, restaking protocols, EigenLayer-style

## Protocol Context

Staking protocols occupy a uniquely high-trust position: user capital is locked into validator key infrastructure, exposing it to consensus-layer risks including slashing that originate entirely outside the smart contract layer. Share price is a direct function of validator performance and beacon chain reward timing, meaning off-chain oracle reports introduce manipulation surfaces not present in purely on-chain yield protocols. Withdrawal queue mechanics create time-asymmetric liquidity risk where the contract's liability (user claims) can diverge materially from its liquid assets for weeks or months, and accounting that fails to model this gap correctly systematically misprices shares.

---

## Bug Classes

### Reentrancy (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Contracts send ETH or interact with ERC721/ERC1155/ERC777 tokens during deposit, withdrawal, or reward claim flows, creating callback windows.
- Read-only reentrancy is especially relevant for protocols that read share prices or reserve balances from external AMMs (Balancer, Curve) while those pools are mid-execution.
- Staking contracts that wrap NFT receipt tokens or use ERC721 for position tracking trigger `onERC721Received` callbacks before state is finalized.

**Detection Heuristics**
1. Identify every external call in non-view functions: `call`, `transfer`, `send`, `safeTransfer`, `safeTransferFrom`, NFT `mint`/`burn`.
2. Verify state writes (balances, totals, share supply, reward debt) occur before any external call, not after.
3. Look for token standards with callbacks: ERC777 `tokensReceived`, ERC721 `onERC721Received`, ERC1155 `onERC1155Received`.
4. For read-only reentrancy: check if view functions or pricing logic read from Balancer, Curve, or Compound pools that may have inconsistent state during a join/exit callback.
5. Check cross-function reentrancy: re-entering a different function on the same contract may exploit shared mutable state even when the direct function has a `nonReentrant` guard.
6. Confirm `nonReentrant` modifier is applied to all functions sharing mutable state, not only the obvious withdraw path.

**False Positives**
- External calls to immutable, non-callback contracts such as standard ERC20 tokens without ERC777 extensions.
- Functions where the only external call is at the very end after all state updates (correct CEI).
- State updates that are idempotent or revert on re-entry regardless of guard presence.

**Notable Historical Findings**
Several staking protocols using ERC777 or ERC721 receipt tokens suffered complete balance drainage because reward distribution or deposit finalization happened after the token mint or transfer hook fired. In one Stakehouse Protocol audit, `GiantMevAndFeesPool.withdrawETH` was drained via reentrancy because idle ETH accounting was decremented before the transfer but balance checks occurred after. Sandclock's deposit function allowed a reentrant call to extract more value than the original withdrawal because the balance update occurred after the ETH transfer. Balancer read-only reentrancy was separately identified in a Cron Finance audit where pool reserve reads inside a callback window returned manipulated values, leading to incorrect pricing.

**Remediation Notes**
Apply the checks-effects-interactions pattern uniformly and add `nonReentrant` to all functions that share state with potential reentrancy entry points. For read-only reentrancy via Balancer, call `balancerVault.ensureNotInVaultContext()` before reading pool state in any view or pricing function. For liquid staking protocols reading from external price sources during oracle callbacks, snapshot the value before initiating any external call.

---

### Precision Loss, Rounding, and Decimal Mismatch (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Share-to-asset conversion uses integer division where rounding direction determines whether the protocol or user bears the truncation loss.
- Reward accumulators multiply small per-second rates by large totals, and premature division of intermediate values causes silent truncation.
- Protocols that accept multiple collateral or reward tokens mix 6-decimal and 18-decimal assets in the same arithmetic without normalization.
- Fee calculations using `amount * FEE_BPS / 10000` allow zero-fee transactions when `amount < 10000 / FEE_BPS`.

**Detection Heuristics**
1. Search for division (`/`) appearing before multiplication (`*`) in the same calculation chain; this is the canonical precision-loss pattern.
2. Verify that `previewDeposit` rounds down (fewer shares issued) and `previewWithdraw` rounds up (more shares burned), both in favor of the vault.
3. Check that `mulDiv` or equivalent precision-preserving libraries are used for share price and reward rate calculations.
4. Scan for hardcoded `1e18` or `10**18` divisors used with tokens that are not 18 decimals.
5. Check `balanceOf` aggregation across multiple tokens without decimal normalization.
6. Look for `totalReward / numOperators` patterns in distribution loops that silently discard the remainder.

**False Positives**
- Rounding within 1 wei that is documented and bounded.
- Protocols using `FullMath.mulDiv` or Solmate's `FixedPointMathLib` throughout.
- Single-token protocols with a known fixed decimal count.

**Notable Historical Findings**
In a Liquid Collective audit, operator reward shares suffered rounding errors because multiple sequential divisions were applied to the same intermediate result instead of a single combined division. yAxis vault's `balance()` function summed raw USDC and WETH balances without decimal normalization, producing nonsensical totals that were then used for share issuance. A Napier audit uncovered that a rounding error in ERC4626 exchange rate calculations, combined with a donation attack, allowed an attacker to steal victim funds entirely. GoGoPool's `recreateMinipool` contained a compounded precision error that caused reassigned AVAX amounts to diverge from what node operators expected.

**Remediation Notes**
Multiply before dividing for all multi-step calculations. Normalize all token amounts to a common 18-decimal precision before any cross-token arithmetic, then convert back at the final transfer step. Use `mulDivUp` for fee calculations and share redemption to ensure the protocol never rounds in the user's favor on exit. Track and redistribute integer division remainders explicitly when distributing to multiple operators or stakers.

---

### Access Control and Authorization Bypass (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Privileged functions controlling reward speed, validator key sets, fee parameters, or pool configuration lack access modifiers or have them only on one of several entry paths.
- Permissionless vault or minipool creation grants the deployer elevated access on a shared staking contract the deployer does not own.
- Callback functions (`onTokenTransfer`, `notifyRewardAmount`) bypass role restrictions that apply to direct calls.
- Node operator registration or delegation is open to arbitrary addresses before a validation step takes effect.

**Detection Heuristics**
1. Enumerate all external and public functions; verify each state-modifying one has an appropriate access control modifier or explicit `msg.sender` check.
2. Trace internal functions to all callers, including permissionless paths, to confirm restricted logic cannot be reached without authorization.
3. Verify callback functions check `msg.sender` against the expected protocol address before processing any state change.
4. Confirm role assignment functions are themselves protected and cannot be called to self-assign elevated roles.
5. Check for single-step ownership transfer without a two-step `pendingOwner` acceptance pattern.
6. Verify that `tx.origin` is never used for authorization in place of `msg.sender`.

**False Positives**
- Intentionally permissionless functions such as public liquidation or reward notification with adequate downstream validation.
- Access control enforced by an upstream proxy or factory not visible in the local scope.
- Functions that only affect the caller's own state with no cross-user impact.

**Notable Historical Findings**
In a Popcorn staking audit, a missing access control check on `changeRewardSpeed` allowed any attacker to deplete reward token balances by setting an extreme distribution rate. GoGoPool's node operator minipool creation had a hijacking vector where an attacker could recreate a minipool assigned to a victim's address by exploiting the state transition sequence. Ethena Labs audits identified that the `SOFT_RESTRICTED_STAKER_ROLE` could be bypassed via token approvals or by routing transfers through a secondary account, undermining the compliance purpose of the role. Multiple Stakehouse Protocol findings showed that giant pool vault authenticity checks were weak, allowing an attacker to drain pools by presenting a fabricated vault address.

**Remediation Notes**
Apply `onlyRole` or equivalent modifiers to every function that modifies reward parameters, validator key configuration, fee settings, or protocol state. Implement two-step ownership transfer for all admin roles in staking contracts. For liquid staking, separately protect `notifyRewardAmount` and `addRewardToken` entry points rather than sharing a single internal function that bypasses caller validation.

---

### Logic Errors and Stale State (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Buyout, transfer, or payee-change operations modify one accounting variable but leave interdependent variables (slope, y-intercept, reward debt) with stale values.
- Minipool or validator slot recycling reuses storage structs without resetting time-tracking fields (`rewardsStartTime`, `avaxAssigned`).
- Loops compute updated state (`newStack`) but subsequent iterations continue reading the pre-update original, causing only the last iteration's result to be applied.
- Multiple functions write to the same storage slot without enforcing mutual exclusion or consistent ordering.

**Detection Heuristics**
1. For every state-changing operation, enumerate all related storage variables and confirm each is updated atomically.
2. Inspect loops that compute a new state value and verify subsequent iterations use the updated value, not the original.
3. Check all transfer and ownership-change functions for dependent mappings that must also be updated: payee, reward debt, approvals, delegation records.
4. Verify that cancellation or liquidation functions zero out all time-tracking and amount fields on recycled structs.
5. Look for `delete` or zero-assignment usage after operations that should invalidate existing state.
6. In upgradeable contracts, verify storage layout is consistent across versions and no slot collisions exist.

**False Positives**
- Lazy evaluation patterns where stale state is intentionally corrected on next access.
- Variables that are always overwritten before being read again.
- State that a separate reconciliation function correctly handles.

**Notable Historical Findings**
Multiple Astaria protocol findings exposed that `setPayee` did not update the vault's y-intercept or slope, allowing a vault owner to account for lien interest that was actually flowing to a different address, eventually enabling fund extraction. The `makePayment` function in the same protocol used the original stack in a loop instead of the progressively updated `newStack`, meaning only the final payment iteration was reflected in the state hash. GoGoPool's `cancelMinipool` omitted resetting `rewardsStartTime`, which then persisted through a recreate cycle causing the node operator reward window to be calculated from an incorrect epoch. In Liquid Collective, `Oracle.removeMember` using an array-swap removal allowed the swapped member to vote a second time in the same epoch because their per-epoch action was tracked by index rather than address.

**Remediation Notes**
Always pass the updated intermediate state as the input to subsequent iterations in loops that transform sequences. When recycling validator or minipool structs, zero all time-tracking, amount, and status fields before reinitializing. For protocols with vault slope and y-intercept accounting tied to lien or position payees, update all dependent vault parameters whenever the payee changes. Track per-epoch oracle actions by member address, not array index.

---

### Unchecked Return Values and Unsafe External Calls (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Low-level `call` or `transfer` return values are ignored, allowing silent failures where user funds are debited but the transfer never succeeds.
- Non-standard tokens (USDT, tokens without return values on `transfer`) are used without `SafeERC20` wrappers.
- Flash loan callbacks or proposal execution engines accept arbitrary `target` and `data` without validating the target or function selector.
- Authorized external contracts (tellers, adapters) cannot be revoked once added, leaving compromised contracts permanently in the permission set.

**Detection Heuristics**
1. Verify all `call`, `transfer`, and `send` return values are checked; prefer `SafeERC20` throughout.
2. Search for `token.transfer` or `token.transferFrom` without `safe` wrappers in any protocol that does not exclusively use tokens with guaranteed revert-on-failure behavior.
3. In proposal execution or keepers, check that `target` addresses are validated against an allowlist and that arbitrary `data` cannot construct unauthorized `approve` or `transfer` calls.
4. Look for authorization grants with no corresponding revocation mechanism.
5. Verify flash loan callbacks validate `msg.sender` is the expected lending pool before executing any state change.

**False Positives**
- Targets restricted to a hardcoded whitelist of trusted immutable contracts.
- Callback validation handled by an upstream router or wrapper not visible in the audited scope.
- Protocols that only use tokens with guaranteed revert-on-failure behavior throughout the entire codebase.

**Notable Historical Findings**
A Sturdy Finance audit found that `_withdrawFromYieldPool` contained a success check after a `return` statement, making the check dead code and allowing failed ETH transfers to pass silently. Bond Protocol audits identified that authorized tellers could not be removed from the callback registry after being set, meaning a compromised teller retained permanent access. In Liquid Collective, Solmate's `safeTransfer` was used with addresses that could be non-contract addresses, as Solmate's implementation does not check code size, allowing transfers to EOAs to appear successful when they should fail.

**Remediation Notes**
Use OpenZeppelin's `SafeERC20` for all token interactions, including `safeApprove(spender, 0)` followed by `safeApprove(spender, newAmount)` for USDT compatibility. Implement revocation for all role or adapter grants. For proposal or keeper execution engines in staking governance, maintain an explicit whitelist of allowed targets and function selectors.

---

### Slippage and MEV (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Rebalancing, reinvestment, or reward compounding functions pass `minAmountOut = 0` or `minAmountOut = inputAmount` (wrong for cross-token swaps) to AMM calls.
- Deadline parameters are set to `block.timestamp`, providing no protection against transaction ordering or delayed inclusion.
- Oracle update transactions are predictable and can be sandwiched: attacker front-runs the update to open a position at the stale price, then back-runs to close at the updated price.
- An arbitrary `account` parameter in rebalance functions allows an attacker to drain funds from any address that has granted approval to the protocol.

**Detection Heuristics**
1. Search all AMM swap calls (`swapExactTokensForTokens`, `exactInputSingle`, `exchange`, etc.) for `minAmountOut` or equivalent parameter.
2. Flag any case where `minAmountOut == 0`, `minAmountOut == inputAmount`, or `deadline == block.timestamp`.
3. Identify functions that accept a user-supplied `account` or `from` address as a fund source for swaps or deposits.
4. Check whether oracle report submissions are publicly visible in the mempool and whether they trigger state changes exploitable by front-running.
5. Look for reward harvesting or reinvestment functions callable by anyone with no slippage floor.

**False Positives**
- Swaps executed through private mempools or MEV-protected relayers.
- `block.timestamp` deadline used only for immediate atomic settlement where no pending queue exists.
- Slippage validated by an upstream coordinator function before the swap call.

**Notable Historical Findings**
A UXD Protocol audit found that `rebalance` and `rebalanceLite` accepted an arbitrary `account` parameter for sourcing quote tokens, allowing an attacker to drain any address that had approved the contract. Olympus Update audits identified that oracle sandwich attacks were profitable because the vault's rebalance logic depended on freshly updated prices that were predictably front-run. In Notional Update, the single-side redemption slippage mechanism was structurally broken, providing no actual price protection. Multiple Liquid Collective findings showed that oracle report submissions were front-runnable by other oracle members who could observe pending reports and submit competing or interfering transactions.

**Remediation Notes**
Derive `minAmountOut` from a Chainlink or TWAP oracle with an explicit acceptable slippage percentage, not from the input amount. Require user-supplied deadlines with a reasonable future timestamp rather than `block.timestamp`. For oracle-dependent rebalancing, add a timelock or commit-reveal scheme to prevent profitable sandwiching. Never accept an `account` or `from` address as a parameter for any function that transfers funds on behalf of that address without explicit on-chain authorization from that address in the same transaction.

---

### Denial of Service and Unbounded Loops (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Reward claim or distribution functions iterate over arrays that grow with each user deposit, validator key, or prediction entry, with no pagination or maximum bound.
- Critical operations (liquidation, unstaking, withdrawal) depend on external token burns or transfers that can be blocked by token pause or blacklist.
- Deterministic `CREATE2` deployment salts allow an attacker to pre-deploy a contract to the expected address, preventing the protocol's deployment from succeeding.
- Dust donations to the pool create a non-zero balance before any shares exist, causing division by zero or share calculation reversion on the first legitimate deposit.

**Detection Heuristics**
1. Search for unbounded `for` or `while` loops over user-controlled arrays (predictions, positions, delegations, validator keys).
2. Identify critical-path external calls (withdraw, liquidate, settle) to tokens with pause or blacklist capability (USDC, USDT, certain NFTs).
3. Check `CREATE2` deployment functions for user-controlled or predictable salts without a `msg.sender` component.
4. Look for `balanceOf(address(this))` or `address(this).balance` used as denominator in share calculations where external donations are possible.
5. Verify that enumerable limits (e.g., `MAX_DELEGATES = 1024`) cannot be cheaply exhausted by a low-cost griefing attack.
6. Check that missing a time-windowed keeper call does not permanently brick a state machine (epoch progression, cycle sync).

**False Positives**
- Loops bounded by a compile-time constant that is not user-controllable.
- External calls to tokens without pause or blacklist features.
- Functions with `try/catch` that handle individual failures without propagating them to the entire batch.

**Notable Historical Findings**
Liquid Collective's `_getNextValidatorsFromActiveOperators` function could be permanently DoSed if any single operator had a funded-equals-stopped count mismatch, blocking all staking operations for the entire protocol. GoGoPool identified that a division by zero could block `RewardsPool.startRewardCycle` if all multisig wallets were disabled simultaneously. Velodrome Finance contained a `MAX_DELEGATES` exhaustion attack where an attacker could delegate 1024 tiny positions to any target address, preventing legitimate delegators from adding further delegations. A MCP prediction market audit found that `claimReward()` iterated over all user predictions with no pagination, allowing an attacker to DoS the function by creating enough predictions to exceed the block gas limit.

**Remediation Notes**
Replace unbounded iteration with paginated functions accepting `startIndex` and `count` parameters, or use a per-user accumulated reward tracker that avoids iteration entirely. For operations that depend on pausable or blacklistable tokens, implement a pull-payment pattern so that a blacklisted recipient does not block operations for all other users. For `CREATE2` deployments, include `msg.sender` in the salt.

---

### Oracle Manipulation and Flash Loan Attacks (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Share price, collateral value, or reward rate is computed from spot AMM reserves sampled at a single point in time without a TWAP.
- Governance voting power is derived from current token balances rather than historical snapshots, enabling flash-loan governance attacks.
- Impermanent loss protection or yield calculations use current pool state, allowing an attacker to manipulate reserves within the same transaction to maximize payouts.
- LP token pricing is calculated from current reserve product rather than a manipulation-resistant formula.

**Detection Heuristics**
1. Identify all pricing calls and verify they use TWAP, Chainlink, or another manipulation-resistant source rather than spot AMM balances.
2. Check governance voting power derivation: any mechanism using `balanceOf` at the current block rather than a prior checkpoint is flash-loan-vulnerable.
3. Look for reward rate or IL protection calculations that read current pool reserves without verification they are not mid-manipulation.
4. Verify oracle data freshness: Chainlink feeds should be checked for staleness and the sequencer uptime flag on L2s.
5. Confirm that price feeds validate round completion (`answeredInRound >= roundId`) and timestamp recency.

**False Positives**
- TWAP oracles with a sufficiently long window that makes within-block manipulation uneconomical.
- Governance using ERC20Votes snapshot-based checkpoints with proposal creation at a prior block.
- Flash loan fees that make the attack unprofitable after accounting for gas and borrow cost.

**Notable Historical Findings**
A Behodler protocol audit identified that the LP pricing formula for `purchasePyroFlan` used current reserve product, making it directly manipulable by flash-borrowing one of the reserve assets to skew the ratio and purchase at an artificially low price. Olympus Update confirmed that an adversary could sandwich oracle update transactions by observing the pending report and opening positions just before it landed. Sentiment's ERC4626 oracle was identified as vulnerable to price manipulation because `convertToAssets` reads current vault state, which can be inflated within a single transaction via donation.

**Remediation Notes**
Use Chainlink price feeds with staleness checks for all collateral and reward token pricing in staking protocols. For protocols that reference AMM reserves for any pricing or reward calculation, implement a minimum TWAP window of at least 30 minutes. For governance, require votes to be based on checkpoints from a block prior to proposal creation to prevent flash-loan participation.

---

### Withdrawal Queue and Multi-step Unstaking Issues (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Withdrawal logic has a dead-code success check: a `return` statement appears before `require(sent)`, making the failure condition unreachable.
- Voting power or reward debt decrements during unstaking apply to `msg.sender` instead of the NFT or position owner, diverging accounting when an approved operator performs the unstake.
- Multi-step withdrawal processes (request, wait, claim) do not validate that the claimer is the same address that initiated the request.
- Withdrawal amount calculations do not account for accrued protocol fees or slippage deductions, resulting in the protocol paying out more than it received.
- Lido or Rocket Pool withdrawal queue limitations can brick a downstream protocol's unstaking path when the queue is at capacity.

**Detection Heuristics**
1. Trace the complete withdrawal path from user action through share burn to token transfer; confirm no `return` or `revert` appears before the success check.
2. In any function with a position owner / caller distinction, verify that accounting decrements (shares, voting power, reward debt) apply to the owner, not `msg.sender`.
3. Check that multi-step withdrawal state (request records) cannot be claimed by a different address than the one that initiated.
4. Verify that withdrawal fee or slippage deductions are computed and applied before the transfer, not afterward.
5. For protocols built on Lido or Rocket Pool, check whether their external withdrawal queue backlog can delay or block protocol-level unstaking indefinitely.

**False Positives**
- Single-step withdrawals where `msg.sender == owner` is always true by design.
- Return-before-check patterns that are gated by upstream guards making them unreachable.
- Protocols where withdrawal fees are intentionally zero.

**Notable Historical Findings**
A Sturdy Finance vault audit found that the ETH transfer success check came after a `return` statement, making it dead code; failed withdrawals were silently treated as successful. FrankenDAO's `_unstake` decremented voting power from `msg.sender` rather than the token owner, allowing approved operators to corrupt the voting accounting of unrelated addresses. Notional Leveraged Vaults' integration with Lido's withdrawal queue was found to brick the unstaking process in an edge case where Lido's queue limit was reached, leaving user funds permanently inaccessible until queue capacity was restored. A Stakehouse Protocol audit found that unstaking did not update the `sETHUserClaimForKnot` mapping, leaving residual claims that could be exploited by earlier stakers against new depositors.

**Remediation Notes**
Place all `require` success checks before any `return` statement and after all state changes. When supporting an operator or approval delegation pattern for unstaking, explicitly pass the position owner address (not `msg.sender`) to all accounting decrements. For protocols that rely on external liquid staking withdrawal queues (Lido, Rocket Pool, Frax), implement a fallback or emergency exit path that does not depend on queue availability.

---

### Vault Share Inflation and First-Depositor Attack (ref: fv-sol-2-c6)

**Protocol-Specific Preconditions**
- The vault follows an ERC4626-style `shares = assets * totalSupply / totalAssets` formula with no virtual offset or dead-share initialization.
- An attacker can be the first depositor (depositing 1 wei) and then donate a large amount directly to the vault contract to inflate `totalAssets` before any other user deposits.
- The vault's `totalAssets()` reads `balanceOf(address(this))` rather than an internal accounting variable, making it sensitive to direct donations.
- No minimum initial deposit requirement or dead-share burn to `address(0)` exists in the constructor.

**Detection Heuristics**
1. Check if `convertToShares` uses the formula `assets * supply / totalAssets` with supply sourced from `totalSupply()` and assets from `balanceOf(address(this))`.
2. Confirm whether the constructor or initializer mints dead shares or enforces a minimum initial deposit.
3. Test whether an attacker can deposit 1 wei, then donate a large amount, and cause the next depositor to receive 0 shares due to rounding.
4. Verify the vault reverts on zero-share mints; note this alone is insufficient if the attacker can front-run before the `require(shares > 0)` check is reached by the victim.
5. Check for `_decimalsOffset()` overrides (OpenZeppelin virtual offset pattern) as evidence of first-depositor protection.

**False Positives**
- Vaults using OpenZeppelin's `_decimalsOffset()` virtual shares mechanism.
- Vaults that mint dead shares to `address(0xdead)` during initialization.
- Vaults where `totalAssets()` uses internal accounting rather than `balanceOf`.
- Permissioned vaults where only a trusted address can be the first depositor.

**Notable Historical Findings**
GoGoPool's ggAVAX vault suffered the classic first-depositor share inflation: an attacker could deposit 1 wei to receive 1 share, then donate AVAX to inflate the exchange rate, making subsequent depositors receive zero shares or a negligible number. The same pattern appeared in Redacted Cartel's AutoPxGmx and AutoPxGlp vaults, where share price manipulation was used to steal underlying assets from existing depositors. In Napier Finance, a combination of rounding error and exchange rate manipulation was sufficient for an attacker to steal victim funds, rated as a high severity finding. Liquid Collective identified that a donate-before-deposit sequence could cause new depositors to receive zero shares due to the interplay between `idleETH` and the share issuance formula.

**Remediation Notes**
Initialize all new staking vaults with dead shares minted to `address(0xdead)` or use OpenZeppelin's virtual offset pattern (`_decimalsOffset() = 3` or higher). Alternatively, track `totalAssets` via an internal variable updated only on deposit and withdrawal, never from `balanceOf(address(this))`. Enforce a minimum initial deposit threshold large enough that the cost of the inflation attack exceeds any realistic profit.

---

### Reward Distribution Flaws (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Reward distribution uses a `rewardPerToken` accumulator that is not updated on every stake or unstake, allowing stale accrual.
- `notifyRewardAmount` or `depositFees` functions can be front-run: an attacker stakes immediately before the reward notification and unstakes immediately after to extract a disproportionate share.
- A cycle-based `syncRewards` function must be called manually at epoch boundaries; late calls cause rewards to be credited to a different set of depositors than intended.
- Reward speed or rate configuration is permissionless or has gaps in access control, allowing unauthorized manipulation.
- Multiple reward tokens are tracked but share accounting state, causing cross-token reward accounting errors.

**Detection Heuristics**
1. Check whether the `rewardPerToken` accumulator is updated on every deposit and withdrawal, not only on explicit reward notification calls.
2. Identify `depositFees` or `notifyRewardAmount` functions that do not require a lockup before rewards become claimable.
3. Verify whether `syncRewards` or epoch-transition functions must be called manually and what happens to rewards if the call is delayed.
4. Check if reward speed configuration functions are properly access-controlled.
5. Confirm that zero `totalSupply` is handled in reward calculations to prevent division by zero.
6. For multi-token reward systems, verify each token's accumulator is tracked independently.

**False Positives**
- Protocols with enforced lockup periods longer than one block preventing same-block stake/unstake.
- Systems using time-weighted average staking balance that makes instantaneous front-running unprofitable.
- Reward rates so low that front-running is economically infeasible after gas costs.

**Notable Historical Findings**
Velodrome Finance contained a suite of reward accounting bugs including front-runnable bribe distributions, incorrect epoch boundary calculations that caused rewards to be measured from the wrong checkpoint, and gauge kills that locked previously claimable distributions permanently. In a Beraji Ko audit, stakers could lose earned aSugar tokens because the reward claim depended on a spot price at claim time rather than at accrual time, enabling sandwich attacks on the claim transaction. GoGoPool found that node operators were slashed for the full validation duration even though rewards were distributed on a 14-day cycle, causing systematic over-penalization. Liquid Collective's `Oracle.removeMember` array-swap approach allowed the swapped member to vote twice in the same epoch, directly corrupting the oracle consensus that drives staking reward reporting.

**Remediation Notes**
Update the `rewardPerToken` accumulator synchronously on every deposit, withdrawal, and transfer operation. Use a per-user `rewardDebt` checkpoint pattern that snapshots the accumulator at the time of balance change. For cycle-based protocols, automate `syncRewards` or make it permissionless with a grace period but ensure late calls do not retroactively disadvantage depositors who were active during the missed window. Lock reward claims for at minimum one block after a stake event to prevent flash-stake extraction.

---

### ERC4626 Vault Non-Compliance (ref: fv-sol-2-c6)

**Protocol-Specific Preconditions**
- `maxDeposit`, `maxMint`, `maxWithdraw`, or `maxRedeem` return non-zero values when the vault is paused, causing integrating protocols to attempt operations that will revert.
- `previewDeposit` or `previewWithdraw` results do not match actual execution, causing integrators that rely on preview functions for slippage checks to receive incorrect amounts.
- `withdraw` and `redeem` burn shares from `msg.sender` rather than `owner`, breaking the ERC4626 delegated withdrawal pattern.
- Rounding direction is incorrect: deposit/mint functions should round against the depositor, and withdraw/redeem should round against the withdrawer.

**Detection Heuristics**
1. Test that all `max*` functions return 0 when the vault is paused.
2. Verify `previewDeposit` rounds down (depositor receives fewer shares) and `previewWithdraw` rounds up (more shares burned per asset withdrawn).
3. Confirm `withdraw` and `redeem` correctly burn from `owner`, check `msg.sender`'s allowance when `msg.sender != owner`, and transfer to `receiver`.
4. Check that `totalAssets()` is not manipulable via direct token donations.
5. Verify router peripheral contracts do not make redundant `approve` calls that cause ERC4626 flows to revert.

**False Positives**
- Documented intentional deviations from ERC4626 with downstream handling.
- Vaults implementing a superset of ERC4626 with explicit additional safety checks.
- Rounding differences bounded to 1 wei that are mathematically acceptable.

**Notable Historical Findings**
GoGoPool's TokenggAVAX vault returned incorrect values from `maxDeposit` and `maxMint` when the contract was paused, causing external protocols that used these functions for deposit validation to proceed and then revert. Multiple Astaria findings showed that `redeemFutureEpoch` transferred shares from `msg.sender` instead of `owner`, breaking delegated redemption. Redacted Cartel's AutoPxGmx vault's share price was manipulable due to a `totalAssets()` calculation that read from `balanceOf(address(this))`, enabling the classic donation inflation attack. A Popcorn audit found that the vault was drainable because its ERC4626 implementation was non-compliant in a way that allowed the exchange rate to be walked to an extreme value.

**Remediation Notes**
Implement `maxDeposit` and `maxMint` with an explicit `if (paused()) return 0` guard. Always burn from `owner` in `withdraw` and `redeem`, and check `allowance[owner][msg.sender]` when caller differs from owner. Use internal accounting for `totalAssets()` rather than `balanceOf(address(this))` to eliminate donation manipulation surfaces.

---

### Token Integration Issues (ref: fv-sol-2-c7, fv-sol-6-c10)

**Protocol-Specific Preconditions**
- The protocol accepts arbitrary ERC20 tokens and records deposit amounts from the `transferFrom` parameter rather than a before/after balance difference, causing over-accounting for fee-on-transfer tokens.
- `safeApprove` is called with a non-zero amount on a token (USDT, USDC) that has a residual non-zero allowance, causing reversion.
- Rebasing tokens (stETH, aTokens) increase in balance between deposit and withdrawal, but the protocol tracks balances at the time of deposit, leading to an effective loss of the accrued rebase.
- Non-standard tokens that return `false` on transfer failure instead of reverting are used without `SafeERC20` wrappers.

**Detection Heuristics**
1. Check for `transferFrom(sender, this, amount)` immediately followed by `balances[user] += amount` without a before/after balance difference.
2. Search for `safeApprove(spender, nonZeroAmount)` calls that may execute when a residual allowance exists.
3. Identify whether rebasing tokens are in scope; if so, verify balance snapshots are taken at the time of withdrawal, not deposit.
4. Confirm `safeTransfer` / `safeTransferFrom` from OpenZeppelin or Solmate is used universally.
5. Look for exact equality checks (`==`) on post-transfer balances, which always fail for fee-on-transfer tokens.

**False Positives**
- Protocols that explicitly document and enforce support only for non-fee, non-rebasing tokens with known fixed decimals.
- Before/after balance diff pattern used consistently throughout the codebase.
- Contracts that only interact with a single known safe token (e.g., WETH only).

**Notable Historical Findings**
Sublime Finance's strategy integration broke when Aave's aToken was used as collateral because the rebasing balance growth was not accounted for in the deposit tracking, causing systematic undervaluation. Multiple Redacted Cartel findings showed that fee-on-transfer token interactions in GMX vault deposits caused an inflated internal balance relative to actual holdings, which later caused withdrawals to fail or drain the pool. Liquid Collective's Solmate-based transfer wrappers passed silently for non-contract addresses because Solmate's implementation does not check code size, bypassing the intent of the safe transfer abstraction. In Gauntlet's protocol, `safeApprove` with a non-zero residual allowance caused deposit configuration to revert for USDT-like tokens, breaking protocol initialization.

**Remediation Notes**
Use before/after balance difference (`balanceAfter - balanceBefore`) for all deposit accounting to be fee-on-transfer and rebase-safe. Always reset allowance to 0 before calling `safeApprove` with a new amount. Use OpenZeppelin's `SafeERC20` library universally rather than Solmate's transfer helpers when supporting arbitrary tokens, as OpenZeppelin checks code size.

---

### Governance and Voting Manipulation (ref: fv-sol-5-c6)

**Protocol-Specific Preconditions**
- Voting checkpoints are written per-transfer; multiple transfers in the same block create separate checkpoints with the same timestamp, and binary search returns the wrong one.
- Staking time bonus for governance weight uses `unlockTime - block.timestamp` with no maximum cap, allowing `type(uint256).max` to produce unbounded voting weight.
- Proposal creation has no minimum holding or voting power threshold, allowing a zero-vote proposal to be submitted and potentially executed.
- Delegation mechanics allow an adversary to force-delegate to a target and exhaust its `MAX_DELEGATES` limit, blocking the target from receiving legitimate delegations.

**Detection Heuristics**
1. Check if voting checkpoints correctly handle multiple updates within the same block timestamp (consolidate rather than append).
2. Verify that staking bonus multipliers applied to unlock time have a hard maximum cap enforced on-chain.
3. Confirm proposal creation requires a minimum token balance or voting power, not just a non-zero balance.
4. Look for delegation limits that can be cheaply exhausted: if creating a delegation costs only gas, a griefing attack is feasible.
5. Verify that `getPastVotes` binary search returns the correct checkpoint for the queried timestamp when multiple updates occur in one block.

**False Positives**
- Checkpoint conflicts within a block that are impossible due to protocol-level transaction ordering guarantees.
- Proposals requiring multi-sig approval before execution regardless of vote count.
- Delegation limits high enough that exhaustion is economically impractical.

**Notable Historical Findings**
FrankenDAO's unbounded `_unlockTime` parameter allowed an attacker to pass `type(uint256).max` and receive an astronomically large staking bonus, dominating governance entirely. Nouns Builder had two distinct voting bugs: multiple checkpoints in the same block caused binary search to return incorrect historical vote counts, and `ERC721Votes` self-delegation doubled voting power by counting the same balance twice. Olympus DAO allowed any address to pass a governance proposal before any VOTES tokens were minted, enabling a single attacker to pass an arbitrary proposal with zero opposition. Velodrome Finance found that bribes and fee emissions could be gamed by voters who desynchronized the bribe-payment timing from the emissions period, collecting bribes without triggering the corresponding gauge emissions.

**Remediation Notes**
Consolidate voting checkpoints within the same block timestamp into a single entry rather than appending a new one. Enforce a hard on-chain maximum for staking unlock time (`block.timestamp + MAX_STAKE_DURATION`). Require a minimum voting power for proposal creation enforced at the contract level. Track per-epoch oracle or governance actions by address rather than array index to prevent double-action via array-swap removal.

---

### Signature Replay and Validation Gaps (ref: fv-sol-4-c4, fv-sol-4-c10, fv-sol-4-c11)

**Protocol-Specific Preconditions**
- `ecrecover` is called directly without checking for an `address(0)` return, which occurs for any invalid signature input; if `address(0)` holds a role or is an initialized mapping key, the check passes.
- Nonces are absent or not incremented after use, allowing the same signature to be replayed indefinitely.
- EIP-712 domain separators omit `chainId` or the contract address, making signatures valid across chains or redeployments.
- Cross-chain deployments share the same signature domain, enabling replay on any chain where the contract is deployed.

**Detection Heuristics**
1. Check all `ecrecover` calls for explicit `require(recovered != address(0))` or equivalent.
2. Prefer OpenZeppelin's `ECDSA.recover`, which reverts on `address(0)`.
3. Verify that signature schemes include a nonce incremented after use.
4. Confirm EIP-712 domain separator includes both `block.chainid` and `address(this)`.
5. Check whether `permit` or authorization signatures have expiration timestamps.
6. Verify that signature inputs use `abi.encode` rather than `abi.encodePacked` for dynamic types to prevent hash collision.

**False Positives**
- Systems where `address(0)` can never hold a valid role or authorization by construction.
- Nonce management handled by a trusted upstream contract not in the audited scope.
- Protocols on a single chain with immutable contracts and no plans for cross-chain deployment.

**Notable Historical Findings**
GoGoPool found that minipool creation signatures lacked sufficient validation, allowing an attacker to hijack another node operator's minipool and cause loss of staked funds. Ondo Finance's KYCRegistry was found to be vulnerable to signature replay: the same KYC approval signature could be submitted multiple times because no per-signature nonce was consumed. Hats Protocol had multiple findings where `address(0)` could effectively own a hat through signature manipulation, causing the safe's signature validation to accept phony signatures in critical multisig operations. Stakehouse Protocol's `deployLPToken` used a cross-chain replayable signature domain, enabling replay attacks across any EVM-compatible chain where the contract was also deployed.

**Remediation Notes**
Use OpenZeppelin's `ECDSA` library for all signature recovery. Include `block.chainid`, `address(this)`, and a per-signer nonce in all EIP-712 domain separators and message hashes. Increment or mark nonces as consumed atomically within the same transaction that validates the signature. For staking protocols operating across multiple chains, verify that operator key registration or delegation signatures are chain-specific.

### Staking Reward Front-Run by New Depositor (ref: pashov-144)

**Protocol-Specific Preconditions**
- Reward distribution uses a `rewardPerToken` accumulator pattern (Synthetix-style) where `rewardPerTokenStored` is updated by dividing pending rewards by total supply
- The stake deposit function increments `_balances[user]` before calling `updateReward(user)` or the equivalent checkpoint function
- A new depositor's balance is recorded at the pre-update `rewardPerTokenStored` value, meaning the user is credited for rewards that accrued before they staked

**Detection Heuristics**
1. Locate the stake deposit function. Check whether `_balances[user] += amount` appears before or after the `updateReward(user)` call.
2. Verify that `rewardPerTokenPaid[user]` is set to the current `rewardPerTokenStored` value after the checkpoint update, not before.
3. Simulate a deposit immediately before a large reward notification: confirm the depositor does not receive a share of rewards that accrued before their deposit.
4. Check for the same ordering issue in delegation or restaking functions where a balance change precedes a reward checkpoint.
5. Verify that `notifyRewardAmount` or reward distribution cannot be called in the same transaction as a deposit to create a front-run opportunity.

**False Positives**
- `updateReward(account)` is called as the first statement of the stake function, before any balance mutation, via a modifier or inline call
- `rewardPerTokenPaid[user]` is set to `rewardPerTokenStored` atomically at the start of every deposit, making the user's baseline always current before their balance increases
- The reward accumulator design does not use a per-user paid checkpoint and instead uses a different mechanism that is not susceptible to this ordering issue

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Apply an `updateReward(account)` modifier or function as the unconditional first step in every stake, withdraw, and getReward function. The modifier must read `rewardPerToken()`, store it in `rewardPerTokenPaid[account]`, and compute the user's pending rewards before any balance change occurs. OpenZeppelin's `StakingRewards` reference implementation places `updateReward` as a modifier to ensure ordering is enforced syntactically.

---
