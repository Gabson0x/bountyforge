# Reserve Currency Protocol Security Patterns

> Applies to: protocol-owned liquidity, reserve currency protocols, OHM-style, bonding mechanisms, treasury-backed tokens, (3,3) staking models, Olympus-style

## Protocol Context

Reserve currency protocols build protocol-owned liquidity through bonding, where users sell LP tokens or collateral assets to the treasury at a discount in exchange for vested governance tokens. Treasury depth provides a backing floor price, while staking mechanics distribute seigniorage income to token holders. The critical attack surface lies in the state aggregators that cache collateral ratios and treasury metrics: stabilization and profit distribution decisions read these cached values without re-syncing, so any sequence of operations that modifies underlying balances before the aggregator is refreshed causes stabilization to act on incorrect information.

Registry-style data structures managing swing traders, market participants, and protocol contracts introduce a second class of vulnerabilities: add/remove function asymmetry, silent role revocation failures, and array/mapping state divergence all corrupt the iteration logic that drives stabilization buy/sell decisions. These structural bugs are compounded by the sensitivity of the staking model to correct epoch accounting and APR calculation, where an ordering error in a single update function can permanently corrupt cumulative reward metrics.

## Bug Classes

---

### Access Control State Mismatch (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Contract maintains a registry of swing traders or other protocol actors tracked in both a mapping (struct with fields including an `active` boolean) and an auxiliary array used for iteration. Addition functions push to the array unconditionally, regardless of the `active` parameter value. A custom `hasRole` override adds a `validRoles[role]` condition beyond the base implementation, causing role revocation to silently fail when `validRoles` is false for the target role. The same registry allows duplicate registrations of the same underlying contract address.

**Detection Heuristics**
Identify registry-style contracts maintaining both a mapping and an array for tracking active entities. Check if add/register functions unconditionally push to the array regardless of the `active` parameter. Look for `hasRole` or similar override functions that add conditions beyond the base implementation. Trace role revocation, renouncement, and transfer paths to see if they depend on the overridden `hasRole` returning true. Check for uniqueness validation on the underlying contract address when adding entries.

**False Positives**
The array is purely informational and not used for balance calculations or iteration in critical paths. The `active` parameter is always `true` in practice, enforced by calling conventions or deployment scripts. Role override behavior is intentional and documented, with separate admin paths for cleanup.

**Notable Historical Findings**
Malt Protocol's SwingTraderManager.addSwingTrader always pushed the `traderId` to the `activeTraders` array even when the `active` parameter was explicitly set to false, corrupting iteration over active traders and causing incorrect balance calculations used in stabilization decisions. A companion finding showed the same contract allowed duplicate trader contract addresses, which compounded the iteration corruption. MaltRepository's overridden `_revokeRole` silently failed when the role being revoked had `validRoles[role] == false`, because the override's `hasRole` returned false even for legitimately-granted roles, making those roles effectively irrevocable.

**Remediation Notes**
Condition the `activeTraders.push()` call on `active == true`. Validate uniqueness of the underlying contract address before adding a new trader entry. When overriding `hasRole`, ensure the override does not break revocation, renouncement, or transfer paths; provide an explicit admin path for cleaning up roles that bypass the `validRoles` guard.

---

### Reward Accounting Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol distributes rewards, profits, or yield over epochs or vesting periods. Accounting variables (cumulative APR, vested amounts, profit totals) are updated conditionally or at the end of a function. Early returns, zero-amount edge cases, or cap-bound logic cause accounting updates to be skipped. Downstream logic depends on the accuracy of these cumulative tracking variables for computing APR averages, vesting schedules, and profit distributions.

**Detection Heuristics**
Look for functions that update cumulative or running-total variables and check for early-return paths or zero-amount guards that skip these updates. Identify cap/clamp logic (e.g., `if (distributed > balance) distributed = balance`) and verify whether the tracking variable adjusts to match the actual distributed amount. Search for `return` statements that occur before state variable assignments, especially in loops processing multiple epochs. Verify that dust-check guards do not skip profit or reward accounting updates.

**False Positives**
Zero-amount epochs genuinely should not contribute to cumulative metrics by design. The skipped update is for a metric that is never read again. A separate reconciliation mechanism corrects drift periodically.

**Notable Historical Findings**
Malt Protocol's RewardThrottle had several reward accounting errors found together: `_sendToDistributor` returned early when the distribution amount was zero, skipping the cumulative APR update for that epoch, which caused `checkRewardUnderflow()` to track cumulative APRs incorrectly across subsequent epochs. A related finding showed that an epoch without profit would fail to carry its cumulative APR checkpoint into the next epoch, so the following epoch's APR calculation started from an incorrect base. LinearDistributor set `previouslyVested` to `currentlyVested` even when the distributed amount was capped by available balance, permanently losing the unclaimed portion of the vesting schedule.

**Remediation Notes**
Decouple accounting variable updates from the distribution guard: update cumulative metrics unconditionally before any zero-amount early return. When distribution is capped by available balance, adjust `previouslyVested` proportionally to the actual distributed amount rather than advancing it to the full `currentlyVested` value. Write invariant tests asserting that the sum of all epoch APR contributions matches the total rewards emitted.

---

### Stale State Dependency (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Contract reads collateral ratios, price targets, or balance-derived metrics from a global state aggregator that caches values from the previous sync. The aggregator is not synchronized before the consuming function executes its core logic. Intermediate operations within the same transaction (token transfers, swaps, auction finalizations) modify the underlying balances that the aggregator should reflect. The stale value influences critical protocol decisions such as stabilization, profit distribution, or price target calculations.

**Detection Heuristics**
Identify global state aggregators that cache balances or derived metrics (e.g., `collateralRatio`, `totalCollateral`). Trace all functions that read from these aggregators and check if a `sync` call precedes the read. Look for intermediate operations between the last sync and the read that modify underlying balances. Check whether the stale value feeds into branching logic, price calculations, or distribution ratios. Pay attention to multi-step functions where early steps modify state that later steps depend on through the aggregator.

**False Positives**
The aggregator uses live `balanceOf` calls instead of cached values. The magnitude of staleness is negligible relative to the decision threshold. Sync is guaranteed to happen in the same transaction via a modifier or hook before any read.

**Notable Historical Findings**
Malt Protocol's `stabilize()` called `auction.checkAuctionFinalization()` (which modifies balances) before calling `impliedCollateralService.syncGlobalCollateral()`, meaning the price target derived from `collateralRatio()` reflected pre-auction-finalization balances and caused incorrect stabilization buy/sell decisions. A companion finding showed `_distributeProfit` read `swingTraderCollateralDeficit` and `swingTraderCollateralRatio` from the same stale service. A third related finding noted that `stabilize()` could incorrectly include undistributed rewards sitting in the overflow pool as part of the collateral calculation, further inflating the apparent collateral ratio.

**Remediation Notes**
Call `impliedCollateralService.syncGlobalCollateral()` (or equivalent) as the first action in any function that derives critical values from the aggregator. Establish a consistent ordering contract: all balance-modifying operations complete, then sync, then read derived values. Enforce this with a modifier or a clearly-named internal helper that combines sync and read.

---

### State Update Ordering (ref: fv-sol-5)

**Protocol-Specific Preconditions**
A function modifies a storage variable and then reads the now-modified value for a different calculation in the same function, or exits via an early return before updating a dependent state variable. Array management uses a swap-and-pop pattern where the index is sourced from a struct field that is zeroed before it is read. Public functions can be called by anyone (including front-runners) to modify shared state that admin functions depend on being at a specific prior value.

**Detection Heuristics**
Search for patterns where a storage variable is set to zero or a new value, then immediately read back for a different computation in the same function. Identify functions with `return` statements that occur before state variable updates (profit, balance, counter). Look for array swap-and-pop patterns where the index is sourced from a struct field that was already modified. Check for public functions that modify shared state and can be called to front-run admin operations.

**False Positives**
The zeroed or modified value is intentionally the correct input for subsequent logic. The early return path is a genuine terminal state requiring no further updates. A front-runnable function has access controls that prevent adversarial invocation.

**Notable Historical Findings**
Malt Protocol's Repository._removeContract zeroed the `currentContract.index` field before reading it to perform the array swap-and-pop, so the swap always targeted index 0 rather than the intended position, corrupting the contract registry. In the same protocol, `sellMalt()` returned early when the dust threshold was hit, before the `totalProfit += profit` line was reached, causing the cumulative profit tracker to undercount. RewardThrottle.populateFromPreviousThrottle was callable by any address and modified `activeEpoch`, which governance relied on being at a specific value when migrating throttle state, enabling a front-run attack that could corrupt the migration. StabilizerNode.stabilize() failed to update `lastTracking` when conditions were not met, causing unnecessary stabilization incentive payouts on subsequent calls.

**Remediation Notes**
Read all storage values that will be needed before modifying them in the same function scope. Update all cumulative and profit-tracking state variables before any conditional early return. Restrict functions that modify shared state used by governance or admin operations to privileged roles. Use local variable copies to capture values prior to mutation when the pre-mutation value is needed later in the same function.
