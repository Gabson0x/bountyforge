# Decentralized Stablecoin Security Patterns

> Applies to: overcollateralized stablecoins, CDP-issued stablecoins, decentralized stablecoins, MakerDAO-style, DAI-style, LUSD-style, collateral-backed peg protocols

## Protocol Context

Overcollateralized CDP stablecoins issue debt tokens against locked collateral at a ratio enforced by liquidation. The entire system invariant - that outstanding stablecoin supply is always backed by more collateral value than debt - depends on accurate, manipulation-resistant collateral pricing, correct liquidation mechanics that can close undercollateralized positions without being griefed, and accounting correctness in vault state across borrow, repay, and stability fee accrual. Any path that allows a user to open a vault, draw stablecoin, or delay liquidation based on an inflated collateral price directly threatens the backing ratio and, at scale, the peg.

Governance parameter management introduces a second systemic risk surface: debt ceilings, collateral factors, liquidation ratios, and stability fees are all tunable by token vote or administrative multisig. Incorrect parameter application - whether through unsafe casting, a missing bounds check, or a race condition between a parameter update and an in-flight transaction - can silently misconfigure the protocol's core risk model. Emergency shutdown mechanisms that must drain all vaults and allow stablecoin holders to redeem pro-rata introduce their own edge cases around vault ordering, partial redemption accounting, and interaction with ongoing liquidation auctions.

## Bug Classes

---

### Oracle Price Manipulation for Collateral Valuation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol reads collateral price from a Chainlink feed or an on-chain AMM without staleness validation. The collateral price feeds directly into the vault health check that determines whether a user can borrow more stablecoin or avoid liquidation. A Chainlink feed with a wide heartbeat and no `updatedAt` check allows a stale high price to persist during a market crash, preventing timely liquidations. An AMM-sourced price without a TWAP window allows a single large flash swap to temporarily inflate collateral value within a transaction, enabling a user to open an undercollateralized vault and withdraw stablecoin before the price reverts.

**Detection Heuristics**
Search for `latestAnswer()` calls, which are deprecated and carry no staleness metadata. Search for `latestRoundData()` where `updatedAt`, `answeredInRound`, or `roundId` are discarded. Check for a staleness threshold: `require(block.timestamp - updatedAt < heartbeatInterval)`. Look for AMM `getReserves()` or `slot0()` used directly as a price source without a TWAP window. Identify whether the collateral price is read once at vault creation or continuously at every health check. Verify that wrapped-asset feeds (stETH/ETH, WBTC/BTC) account for depeg scenarios through a secondary deviation check.

**False Positives**
Protocol uses a dual-oracle design where both Chainlink and a TWAP must agree within a deviation threshold before a price is accepted. A circuit breaker pauses vault operations when oracle freshness degrades below a configurable threshold. Collateral type is an on-chain stablecoin whose price is enforced by a separate stability mechanism and is treated as 1:1 by explicit governance decision.

**Notable Historical Findings**
Multiple MakerDAO collateral integrations over the years have required oracle security module (OSM) delays to prevent same-block price manipulation from bypassing liquidation. Angle Protocol's oracle integration was found to lack staleness checks, allowing a Chainlink feed that had not updated within several hours to produce a price accepted as live. Liquity's direct Chainlink integration includes multiple fallback and staleness checks precisely because the protocol has no governance to react to oracle failures in real time; any fork that removes those checks loses the entire safety mechanism.

**Remediation Notes**
Use `latestRoundData()` and validate all five return values: positive answer, non-zero `updatedAt`, freshness within the declared heartbeat, `answeredInRound >= roundId`, and answer within `minAnswer`/`maxAnswer` circuit breaker bounds. For AMM-sourced prices, use a TWAP of at least 30 minutes and cross-check against a Chainlink feed with a maximum deviation bound. For wrapped assets, add a secondary depeg check using a dedicated ETH/stETH or BTC/WBTC feed before accepting the unwrapped price.

---

### Liquidation Mechanism Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Liquidation functions share a global pause flag with borrowing or repayment, so pausing one operation disables the ability to close undercollateralized positions. Health factor checks read collateral value without first refreshing oracle state or accruing pending interest, causing a vault that has just crossed the liquidation threshold to appear healthy. Dutch auction liquidation mechanisms contain incorrect bid validation that allows winning bids below the reserve price, or permit re-entrancy during the callback that lets a bidder manipulate vault state before the auction finalizes. Liquidation penalty and bonus calculations use integer division that silently truncates to zero for small vaults, making liquidation economically irrational for sub-dust positions.

**Detection Heuristics**
Check whether liquidation functions share the same `require(!paused)` guard as user-facing deposit or repay functions. Verify that `_accrueInterest()` or equivalent is called before any health factor read in the liquidation path. In Dutch auction contracts, trace the bid validation path: does it enforce `bid >= reservePrice`? Check for reentrancy via `onERC721Received` or similar callbacks triggered during collateral transfer. Compute the liquidation bonus for positions at the dust threshold - does it round to zero? Verify that partial liquidation correctly updates vault state so the remaining position is either healthy or fully closeable.

**False Positives**
Protocol has a dedicated liquidation pause flag independent of all other pause switches. Health factor reads are always preceded by an interest accrual modifier at the function entry point. Minimum vault size enforced at creation prevents sub-dust positions from existing.

**Notable Historical Findings**
MakerDAO's multi-collateral DAI system has an extensive liquidation 2.0 architecture precisely because the original liquidation 1.0 was subject to auction griefing and zero-bid attacks during the March 2020 market crash, when a single bidder acquired collateral for near-zero DAI by being the only participant during network congestion. Liquity's liquidation system allows permissionless callers but requires the Stability Pool to have sufficient LUSD; when the pool is empty, liquidations fall through to a redistribution mechanism, and the interaction between these two modes has been the subject of multiple edge-case analyses. Angle Protocol had a finding where the liquidation path could be blocked by a third party calling a related function with carefully crafted state, turning the permissionless liquidation into a griefable one.

**Remediation Notes**
Assign liquidation functions a dedicated pause flag that is never set by general protocol pause logic. Always accrue interest before reading vault health in the liquidation path. Dutch auction bids must be validated strictly at or above the reserve price before executing any callback. Enforce a minimum collateral size at vault creation that guarantees the liquidation bonus is always above gas cost.

---

### Governance Parameter Manipulation (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Governance controls debt ceilings, collateral ratios, liquidation thresholds, and stability fees via on-chain proposals. Parameter update functions lack input validation, allowing governance to set a collateral factor above 100%, a debt ceiling to zero (bricking borrowing), or a stability fee to a value that overflows the accrual accumulator. A proposal that sets `liquidationRatio` below the current outstanding collateral ratio of all active vaults instantly makes every vault liquidatable simultaneously. Flash loan governance attacks are possible when voting power is not snapshotted before proposal creation.

**Detection Heuristics**
Enumerate all setter functions for protocol risk parameters and check for upper and lower bound validation on each. Verify that `liquidationRatio` setters cannot be set below `collateralizationRatio` without a migration path for existing vaults. Check that stability fee and interest rate setters validate against an overflow boundary for the accumulator data type. Look for governance vote paths where voting power is snapshotted at or after proposal creation rather than strictly before. Identify any parameter setter that is callable by an EOA admin without a timelock.

**False Positives**
All parameter setters are behind a multi-step timelock that provides sufficient public observation time. Parameter bounds are enforced in a configuration contract reviewed separately from the core protocol. A formal verification proof exists that the parameter space is globally safe.

**Notable Historical Findings**
MakerDAO's governance system includes an executive vote spell mechanism with a governance security module delay precisely to allow the community to react to malicious spell proposals before they execute. Beanstalk, while not a CDP protocol, demonstrated the flash loan governance attack vector in a single transaction that borrowed governance tokens, passed a malicious proposal, and drained the treasury. Compound's governance has had multiple incidents where incorrect parameter values were submitted in proposals, including a distribution formula error that accidentally allocated far more COMP than intended.

**Remediation Notes**
Add explicit `require` bounds on every risk parameter setter: `liquidationRatio` must be above `collateralizationRatio`, stability fees must be within an economically reasonable range, and debt ceilings must be positive. Snapshot voting power at the block immediately preceding proposal submission, not at the block of the vote. Enforce a governance delay sufficient for the community to observe and cancel malicious proposals.

---

### Vault Accounting and Dust Limit Bypass (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol enforces a minimum vault size (dust limit) to prevent uneconomical positions. The dust check is applied at vault creation but not at partial repayment, allowing a user to repay all but a sub-dust amount and leave a position that can never be profitably liquidated. Vault accounting stores debt as a normalized amount using a rate accumulator; casting this normalized value to a smaller integer type silently truncates the precision, causing debt to be recorded as less than it actually is. A vault's collateral and debt are stored as separate mappings that can diverge if the collateral withdrawal path updates one but reverts before updating the other.

**Detection Heuristics**
Check the dust limit validation path: is it applied only at `openVault` and `borrow` time, or also at `repay` time to prevent leaving sub-dust residues? Search for unsafe casts from `uint256` normalized debt to `uint128` or `uint96` in vault storage structs. Verify that collateral withdrawal and debt repayment are atomic: if either reverts, both must revert. Check whether `normalizedDebt * rateAccumulator` can exceed the storage type before casting. Trace the vault state after a sequence of partial borrows and partial repayments to confirm the final debt matches the sum of all borrow amounts minus repayments.

**False Positives**
Protocol enforces the dust limit on both entry and exit by requiring that after any operation, the vault is either above dust or has zero debt. Vault storage uses `uint256` throughout and no downcasting occurs. Collateral and debt updates are in a single storage write to an atomic struct.

**Notable Historical Findings**
MakerDAO's `dust` parameter applies on both open and close sides; the MIP that introduced it was specifically motivated by cases where small vault remnants could not be liquidated profitably. Liquity enforces a minimum net debt of 2,000 LUSD at all times when a trove is open, preventing sub-threshold remnants after partial repayment. A generalized finding across multiple CDP protocols is that `uint128` debt storage without overflow checks on accumulation fails silently at high interest rates over long time periods.

**Remediation Notes**
Apply the dust check at every operation that can reduce vault debt, not only at creation. Use `uint256` for all intermediate debt calculations and only downcast to storage types after verifying the value fits. Make collateral and debt updates atomic within a single function: revert both if either fails.

---

### Stability Fee and Interest Accrual Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol accrues stability fees using a rate accumulator that multiplies the per-second rate by elapsed time. The accumulator is stored as a fixed-point value; if the per-second rate and the time delta are both large, the multiplication overflows before truncation. Accrual is lazy: the accumulator is only updated when a vault is touched, meaning long-dormant vaults accrue no interest until a user interacts. A stale accumulator read can understate outstanding debt and allow a user to redeem collateral without paying accrued fees. Fee revenue credited to the protocol surplus buffer uses a different calculation path than the user-facing debt display, creating a discrepancy that can be exploited to drain the surplus.

**Detection Heuristics**
Search for `rmul` or equivalent fixed-point multiplication in the accumulator update path and check for overflow protection. Verify that fee accrual is forced before any vault state read that informs a user-initiated operation. Check whether the surplus buffer crediting logic uses the same accumulator snapshot as the user-facing debt calculation. Look for `block.timestamp` in the accrual calculation and verify it cannot be manipulated by a miner to skip accrual. Verify that the initial rate accumulator value is exactly `1 RAY` (1e27) and that division in `normalizeDebt` rounds correctly.

**False Positives**
Protocol uses a formal fixed-point library (e.g., DSMath) that has been audited for overflow. Accrual is forced by a modifier on every state-reading function, making lazy accrual impossible. Accumulator precision is high enough that truncation errors are sub-wei per vault per year.

**Notable Historical Findings**
MakerDAO's `jug.drip()` must be called before any stability fee-sensitive operation; the protocol enforces this through keeper incentives but the contract itself does not force accrual before reads. A theoretical attack on Liquity's interest-free model would involve borrowing LUSD, waiting for the base rate to decay toward zero, and redeeming at the lower fee - the base rate decay formula uses block timestamps and would be manipulable by a miner in a proof-of-authority context. Several CDP forks have been found with accumulator overflows at high interest rates due to using `uint128` for the rate ray instead of `uint256`.

**Remediation Notes**
Force accumulator refresh before every vault read that influences a financial outcome. Store rate accumulators as `uint256` and use overflow-safe fixed-point multiplication. Ensure that the debt calculation path used to debit the user and the revenue path used to credit the surplus buffer share the exact same accumulator snapshot within a single transaction.

---

### Collateral Ratio Check Bypass (ref: fv-sol-5)

**Protocol-Specific Preconditions**
The collateral ratio check is the core safety invariant: outstanding debt divided by collateral value must remain below the protocol's liquidation threshold. This check can be bypassed if: the collateral price is read before a flash loan manipulation reverts; the check is only applied on `borrow` calls but not on collateral withdrawal; a reentrancy vector allows state to be modified between the ratio check and the state update; or a batch operation processes multiple vaults and applies the ratio check only at the end, allowing intermediate states to violate the invariant.

**Detection Heuristics**
Enumerate every public function that modifies vault state: `borrow`, `withdrawCollateral`, `repay`, `liquidate`, and any batch variant. For each, verify that the collateral ratio check is applied after all state changes and not before. Check for reentrancy via ERC-777 `tokensToSend` hooks, ERC-4626 callbacks, or ETH sends that could allow a user to re-enter a function between the state change and the ratio validation. In batch operation contracts, verify that the invariant check is applied per-vault, not only on the aggregate.

**False Positives**
All collateral is ERC-20 tokens with no transfer hooks and the protocol does not accept ERC-777 or native ETH as collateral. Reentrancy guard is applied at the entry point of every vault-modifying function. The oracle is a manipulation-resistant TWAP, making same-block flash loan attacks economically infeasible.

**Notable Historical Findings**
Reflexer Finance (RAI) identified a theoretical batch-operation reentrancy vector in safe engine operations. MakerDAO's collateral adapter pattern carefully separates the join/exit of collateral from the vault manipulation, with the ratio check applied by `vat.frob` after all collateral movements, to prevent reentrancy from the collateral token itself. Multiple DeFi protocols have been exploited through ERC-777 hooks that allowed reentrance into a borrow function before the debt balance was updated, resulting in double-borrow at the same collateral.

**Remediation Notes**
Apply collateral ratio validation as the last step in every function that modifies vault state, after all balance updates are written. Add `nonReentrant` to all vault-modifying functions. Explicitly reject ERC-777 tokens and other tokens with transfer hooks as collateral types, or handle them in dedicated adapters that disable reentrancy before any collateral movement.

---

### ERC4626 Vault Edge Cases (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
Protocol wraps a stablecoin or yield-bearing token using an ERC4626 vault with share-based accounting. A minimum share threshold exists to prevent dust positions. `totalAssets()` is derived from the vault's token balance, which is manipulable via direct transfers. Cooldown or withdrawal delay mechanisms interact with global configuration changes (toggling cooldown on/off). Deposit and withdrawal of native tokens are asymmetric.

**Detection Heuristics**
Check if `totalAssets()` uses raw `balanceOf` on the vault address, which is manipulable via direct token transfers. Look for minimum share thresholds and calculate the cost to inflate the vault to deny new depositors. Verify that `_decimalsOffset()` provides sufficient protection against first-depositor inflation attacks. Trace cooldown state transitions when global settings change and confirm that existing user-specific timers respect the new configuration. Check for asymmetric native token handling and the presence of a `receive()` function if any withdrawal path sends native ETH.

**False Positives**
Vault is initialized atomically with a meaningful first deposit in the deployment transaction, preventing inflation. Protocol always uses a virtual shares/assets offset that makes inflation attacks uneconomical. Cooldown settings are documented as immutable after deployment and the toggle scenario is operationally impractical.

**Notable Historical Findings**
Ethena Labs' StakedUSDe was found to have three related ERC4626 issues in the same audit: an attacker could front-run the first deposit by sending tokens directly to inflate `totalAssets`, causing subsequent depositors to receive zero shares until they deposited more than the inflated threshold; users who had started a cooldown period were unable to withdraw even after governance disabled the global cooldown duration, because the per-user `cooldownEnd` timestamp was not cleared on toggle; and the vault supported ETH withdrawal but lacked a `receive()` fallback, making direct native token deposits impossible.

**Remediation Notes**
Use a virtual offset (e.g., `1e6`) in share conversion math to raise the cost of inflation attacks above economic viability. When the global `cooldownDuration` is set to zero, clear or bypass any existing per-user cooldown timestamps in the `unstake` path. Add `receive() external payable {}` if any protocol path can push native ETH to the vault. Deploy the vault with an initial protocol-owned deposit in the same transaction to prevent the zero-supply first-depositor window.

---

### Role Restriction Bypass (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Protocol enforces role-based access control with blacklist and whitelist roles that restrict token operations (mint, burn, transfer, deposit, withdraw). Roles are not mutually exclusive: an address can hold both blacklisted and whitelisted roles simultaneously. Restriction checks inspect only `msg.sender` or the caller but not the token owner or the actual beneficiary. The ERC4626 `withdraw`/`redeem` three-address signature (`caller`, `receiver`, `owner`) is not fully checked against all restriction roles.

**Detection Heuristics**
Enumerate all role-based restriction checks and verify they cover all relevant addresses: `msg.sender`, `from`, `to`, and `owner`/`controller`. Check whether blacklist and whitelist roles are mutually exclusive or if overlapping roles are possible. Trace the ERC4626 `withdraw`/`redeem` paths with the three-address signature and verify restrictions on all three. Look for Sybil bypass opportunities: can a restricted address transfer tokens to a second address they control? Check that `_beforeTokenTransfer` hooks enforce restrictions consistently across all transfer states.

**False Positives**
Protocol intentionally allows restricted addresses to perform certain operations as documented (e.g., soft-restricted users can trade on secondary markets). Bypass requires cooperation from a trusted party. Economic impact of the bypass is net-positive for the protocol (e.g., burning reduces supply and strengthens the peg).

**Notable Historical Findings**
Ethena Labs' UStb and StakedUSDe contracts were found to have five role restriction bypass variants in two audit rounds. A blacklisted user who also held the WHITELISTED_ROLE could burn tokens during the WHITELIST_ENABLED transfer state because the burn path checked whitelist membership but not blacklist membership. FULL_RESTRICTED stakers could withdraw by approving an unrestricted third-party address to call `withdraw` on their behalf, since the restriction check only covered `caller` and `receiver` but not `_owner`. SOFT_RESTRICTED stakers could bypass their restriction through a similar approval-based mechanism. In a separate finding, a soft-restricted user could redeem stUSDe for USDe via a collateral redemption path that lacked the restriction check.

**Remediation Notes**
Enforce mutual exclusivity of blacklist and whitelist roles: granting one should automatically revoke the other. In the `_beforeTokenTransfer` hook, check both whitelist and blacklist status for the `from` address in all code paths. In ERC4626 `_withdraw`, check the restriction role for all three of `caller`, `receiver`, and `_owner`. Audit all code paths that result in a token balance change (burn, withdraw, redeem, transfer) for consistent role enforcement.

---

### Peg Defense Arbitrage Attack Surface (ref: fv-sol-8)

**Protocol-Specific Preconditions**
Protocol exposes a redemption path that allows stablecoin holders to redeem 1 USD worth of collateral per stablecoin. This path is intended as a peg defense mechanism but is callable permissionlessly, allowing an adversary to use it to extract specific collateral types at a discount if the redemption ordering selects undercollateralized vaults first. Redemption fees are computed on stale base rate state, allowing a user to front-run a large redemption with their own smaller redemption to manipulate the base rate used for fee calculation. The redemption path does not enforce slippage protection on the collateral output, making it sandwichable.

**Detection Heuristics**
Identify the redemption function and trace how it selects which vaults to redeem from. Check if vault selection is deterministic (e.g., lowest ICR first) and whether it can be manipulated by an attacker who opens a targeted vault just before a redemption. Verify that the base rate used for fee calculation is updated atomically with the redemption. Look for any redemption path that executes a collateral swap with no `minAmountOut` parameter. Check whether the redemption path can be used to grief a specific vault owner by repeatedly partially redeeming from their vault to reduce their collateral.

**False Positives**
Redemption fees are high enough to make arbitrage consistently unprofitable. Redemption path is rate-limited per block or per epoch to prevent large-scale attacks. Vault ordering for redemption is randomized or uses a time-weighted metric that cannot be gamed in a single transaction.

**Notable Historical Findings**
Liquity's redemption mechanism selects troves with the lowest ICR first; this is the intended behavior and creates an incentive for vault owners to maintain high ICR, but it has been analyzed extensively as a potential griefing vector where a targeted vault can be partially redeemed from repeatedly. Fee front-running on the base rate has been discussed in Liquity's documentation as a known property of the system that is mitigated by the base rate decay function but not fully eliminated. Angle Protocol's redemption path was identified as subject to MEV extraction due to lack of output slippage bounds.

**Remediation Notes**
Ensure the redemption base rate is updated before fee calculation in the same transaction, not lazily from a prior block. Add a minimum collateral output parameter to the redemption interface that the caller can set to prevent sandwich attacks. Document vault selection ordering in the specification and verify it in invariant tests that simulate adversarial vault creation immediately before redemption.

---

### Emergency Shutdown Edge Cases (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Emergency shutdown is designed to freeze all protocol operations and allow stablecoin holders to redeem pro-rata against the collateral pool. Edge cases arise when: shutdown is triggered while an auction is in progress, leaving collateral locked in the auction contract; vault owners who have already been liquidated partially receive incorrect redemption claims; the settlement price used for collateral valuation at shutdown is taken from a single oracle snapshot that can be manipulated immediately before the shutdown transaction; or the shutdown itself can be triggered by a governance vote that is subject to flash loan attack.

**Detection Heuristics**
Trace the shutdown trigger: is it callable by a single key, a multisig, a governance vote, or automatically by an oracle failure? For governance-triggered shutdown, check if voting power can be flash-borrowed. Verify that in-progress auction state is handled at shutdown: are auctions cancelled, or can they complete after the freeze? Check whether the settlement price is taken from a single oracle read or from a time-delayed price feed. Verify that post-shutdown vault claim calculation correctly handles partially liquidated vaults. Check for any function that is callable during shutdown when it should be frozen, or frozen when it should remain callable (e.g., collateral withdrawal after setting vault debt to zero).

**False Positives**
Emergency shutdown is triggered only by a community-controlled multisig with a long delay, making flash loan governance attacks impractical. The oracle used for the shutdown settlement price has a time-delay module that prevents same-block manipulation. In-progress auctions at shutdown time have been formally specified to complete before the collateral distribution begins.

**Notable Historical Findings**
MakerDAO's emergency shutdown module (ESM) requires a specific amount of MKR to be burned to trigger, making it resistant to flash loan attacks; the protocol went through extensive specification of how in-progress auctions and undercollateralized vaults are handled at shutdown. Liquity has no emergency shutdown in the traditional sense; instead, it has a recovery mode triggered by system-level collateral ratio thresholds, and the interaction between recovery mode and the Stability Pool has been a significant area of formal verification effort. A generalized CDP fork finding is that the settlement price oracle at shutdown is not the same as the operational oracle, creating a price discrepancy window.

**Remediation Notes**
Use a time-delayed or volume-weighted oracle snapshot for the shutdown settlement price rather than a spot read at the moment of shutdown. Specify and test the exact behavior of in-progress auctions at shutdown: either cancel them and return collateral to vaults, or allow them to complete before the shutdown distribution begins. Ensure the shutdown trigger cannot be activated by flash-borrowed governance tokens by requiring a minimum holding period before votes count.

---

### Token Decimal Mismatch in Collateral Accounting (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Protocol accepts multiple collateral types with different decimal precisions (WBTC: 8, USDC: 6, standard ERC-20: 18). Collateral amounts are stored in a normalized 18-decimal format, but the normalization conversion is missing or incorrectly applied for non-18-decimal tokens. Oracle prices for these tokens are returned by Chainlink in 8-decimal format; combining an 8-decimal price with an 18-decimal amount without explicit scaling produces a value off by 10^10. A single collateral adapter contract handles multiple tokens and applies a hardcoded scaling factor that is correct for one token but wrong for another.

**Detection Heuristics**
Identify all collateral types the protocol accepts and their native decimal counts. Trace the code path from collateral deposit to vault state storage: is there a `decimals()` call or a hardcoded scaling factor? Verify that oracle price decimals are explicitly accounted for at the integration point, not assumed to be 18. Look for `10**18` literals in collateral valuation formulas and check whether they should be `10**token.decimals()`. Test a USDC (6 decimal) deposit and verify the vault records the correct 18-decimal normalized amount.

**False Positives**
Protocol only supports WETH and DAI-like 18-decimal tokens, enforced by a governance-controlled whitelist that explicitly rejects non-18-decimal tokens. Decimal normalization is handled in a shared adapter library that has been independently audited. All oracle feeds are normalized to 18 decimals before being consumed by the core protocol.

**Notable Historical Findings**
USSD had at least seven decimal-related findings in a single audit including inverted base/rate pairs and incorrect decimal precision in oracle wrappers, all of which affected collateral valuation. Multiple CDP protocol forks of MakerDAO incorrectly adapted the `ilk.spot` calculation when adding non-18-decimal collateral, resulting in collateral ratios that were either 10^10 too high or too low. A common finding in Chainlink integrations is that `latestRoundData()` returns prices in 8 decimals while the protocol assumes 18, with the mismatch only manifesting at extreme price values.

**Remediation Notes**
Read `token.decimals()` dynamically in all collateral adapter contracts and compute the scaling factor at initialization or per-transaction rather than hardcoding. Normalize Chainlink oracle output to 18 decimals by reading `feed.decimals()` and scaling accordingly. Add integration tests for each supported collateral type that verify vault accounting is correct at multiple price points.

---

### Reentrancy via Collateral Token Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**
Protocol accepts ERC-777 tokens or tokens with transfer hooks as collateral. When a user repays debt or closes a vault, the protocol transfers collateral back to the user before updating the vault's debt balance. An ERC-777 `tokensReceived` hook on the user's address re-enters the vault's borrow function while the debt state still shows the pre-close balance, allowing the user to borrow against collateral that is simultaneously being returned. Alternatively, a user receiving ETH from an ETH-collateral vault through a `call{value:}` transfer can re-enter a borrowing function during the ETH receipt.

**Detection Heuristics**
Identify all code paths that transfer collateral to a user-controlled address: `withdrawCollateral`, `repay`, `liquidate`, and `emergencyShutdownClaim`. Check whether the transfer occurs before or after the vault state update that removes the corresponding debt or collateral balance. Search for `nonReentrant` modifiers on all vault-modifying functions. Identify whether ERC-777 tokens are explicitly excluded from the collateral whitelist. Check ETH transfer paths for `call{value:}` followed by vault state updates.

**False Positives**
All collateral is restricted to a whitelist that contains only standard ERC-20 tokens without callbacks, enforced at the adapter level. `nonReentrant` is applied to all vault entry points and re-entrant calls revert. Checks-effects-interactions is applied correctly: vault state is fully updated before any external transfer in all code paths.

**Notable Historical Findings**
MCDEX Mai Protocol had reentrancy possibilities in its deposit, withdraw, and insurance fund functions where collateral transfers were not guarded by a reentrancy lock. A finding in a Fei Protocol integration showed that ERC-777 tokens used as collateral could allow a borrow during the deposit callback, effectively allowing collateral to be double-counted. Dexe governance contract interactions showed reentrancy via ERC721 `onERC721Received` callbacks that re-entered state-modifying functions before they completed their updates.

**Remediation Notes**
Apply `nonReentrant` to all vault-modifying functions. Follow checks-effects-interactions strictly: update all vault state (debt, collateral balance, vault status) before making any external transfer. Restrict collateral types to a protocol-controlled whitelist that explicitly excludes ERC-777 tokens and tokens with `beforeTokenTransfer` or `afterTokenTransfer` hooks that can invoke arbitrary logic.

---
