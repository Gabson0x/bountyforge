# Yield Protocol Security Patterns

> Applies to: yield farming, yield aggregators, strategy vaults, auto-compounders, liquidity mining, ERC-4626 vaults, Yearn-style, Convex-style, reward distribution protocols

## Protocol Context

Yield protocols are distinguished by their dependency on multiple external protocol integrations simultaneously - a single vault may interact with Curve, Aave, Convex, and Uniswap in a single transaction, meaning any mismatch in assumptions about external state (exchange rates, borrow indexes, token decimals) compounds into accounting errors. Reward accounting is uniquely complex because users enter and exit positions asynchronously, requiring per-user checkpointing of global reward accumulators before any balance-changing operation; failure to do so enables retroactive reward manipulation. The share-price model used by ERC-4626-style vaults introduces a class of donation-based inflation attacks where a first depositor can manipulate the share-to-asset exchange rate to steal subsequent depositors' funds, a problem endemic to the category and absent from most other protocol types.

---

## Bug Classes

### First Depositor Share Inflation Attack (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

- Vault uses shares-based accounting where share price = `totalAssets / totalSupply`
- `totalSupply` can reach zero (no dead shares minted at deployment)
- `totalAssets()` reflects direct token balance (donations affect share price)
- No virtual offset (`_decimalsOffset`) or minimum deposit enforcement on first deposit

**Detection Heuristics**

- Identify vaults where `totalSupply == 0` is handled with a `1:1` branch rather than a virtual offset
- Confirm that `totalAssets()` includes `token.balanceOf(address(this))` without exclusion of donated amounts
- Check that `deposit()` reverts when `shares == 0` would result
- Look for absence of `_decimalsOffset()` override in OpenZeppelin ERC4626 subclasses
- Confirm no dead shares are minted to `address(0xdead)` or equivalent in the constructor or first deposit

**False Positives**

- Vaults using OpenZeppelin ERC4626 with a non-zero `_decimalsOffset()` return are protected by design
- Protocols that mint dead shares (e.g., `1000 shares to address(0)`) on first deposit
- Vaults that enforce a minimum deposit threshold high enough to make the attack economically infeasible
- Protocols tracking assets separately from raw token balance (donated tokens do not affect `totalAssets`)

**Notable Historical Findings**

Napier, GoGoPool, BadgerDAO, Sense, and Rubicon all suffered variants of this attack. In each case, an attacker deposited a nominal amount (1 wei), then directly donated a large token balance to the vault to inflate the exchange rate before a victim's deposit was processed. The victim's deposit rounded to zero shares while the attacker redeemed the inflated single share for nearly all vault assets. Redacted Cartel's AutoPxGmx and AutoPxGlp vaults were drained via the same mechanism. The pattern appears in protocols that forked vault code without auditing the first-deposit path.

**Remediation Notes**

Use OpenZeppelin ERC4626's virtual offset pattern (`_decimalsOffset()` returning 3-8) which adds `10**decimalsOffset` virtual shares and 1 virtual asset to all conversion calculations, making inflation attacks require impractically large donations. As an alternative, mint dead shares (`1000 * 10**decimals`) to `address(0xdead)` on the first deposit and require a minimum initial deposit. Always ensure `deposit()` reverts on zero shares computed.

---

### Reward Distribution and Accounting Errors (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

- Protocol distributes rewards using `rewardPerTokenStored` accumulator pattern (Synthetix-derived)
- User reward state (`userRewardPerTokenPaid`) is not checkpointed before balance-modifying operations
- Reward calculation applies boost multipliers that reference current state retroactively
- Functions that unstake, re-stake, delegate, or modify lock duration do not call `updateReward` first
- `totalSupply` or user balance can reach zero mid-cycle causing division-by-zero or reward loss

**Detection Heuristics**

- Trace every function that calls `_mint`, `_burn`, `transfer`, or modifies `balanceOf` and verify it calls `updateReward(account)` first
- Look for boost or lock-duration setters that modify multipliers applied inside `earned()` without a prior checkpoint
- Check unstake logic for operations that subtract total pool shares rather than user shares
- Verify that reward token configuration changes (adding or replacing a reward token) force a full epoch flush before taking effect
- Check the first-claim path when `totalSupply == 0` to confirm `rewardPerToken()` returns early without division

**False Positives**

- Protocols using time-weighted average balances (TWAB) checkpointing where historical snapshots make retroactive manipulation impossible
- Systems where rewards are pushed (distributed pro-rata at a point in time) rather than pulled (accumulated continuously)
- Contracts where the `updateReward` modifier is applied at the inherited ERC20 `_beforeTokenTransfer` hook, covering all paths

**Notable Historical Findings**

Blueberry lost reward accounting across multiple findings in a single audit - users depositing extra funds into ICHI positions lost all accrued ICHI rewards because the position update did not checkpoint rewards first. GoGoPool's slashing logic operated on full slash duration regardless of actual accrual period. Sense Finance had a compounding error where the `pounder` reward was excluded from xPYT auto-compound calculations. Velodrome Finance contained at least six reward accounting findings in a single review: incorrect epoch boundary calculations, totalSupply caching in the reward distributor, undistributed rewards not rolling over, and bribe/fee emissions gameable by just-in-time voters.

**Remediation Notes**

Apply the Synthetix `updateReward(address account)` modifier unconditionally to every function that changes `balanceOf`, `totalSupply`, lock duration, or boost multiplier. The modifier must update `rewardPerTokenStored`, `lastUpdateTime`, and the caller's `rewards[account]` and `userRewardPerTokenPaid[account]` before the state change executes. For protocols with multiple reward tokens, apply the modifier for all active reward tokens. Never clear `rewards[account]` unless a non-zero transfer to the user has been confirmed.

---

### Stale Cached State Desynchronization (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

- Protocol caches values from external lending protocols (borrow indexes, exchange rates, cumulative prices)
- Cached values are not refreshed before use in liquidation, withdrawal, or interest calculations
- Time elapses between cache updates, allowing values to diverge from live protocol state
- Aggregator protocol tracks position state independently of the underlying protocol it wraps (e.g., Morpho over Aave)

**Detection Heuristics**

- Search for `lastPoolIndexes`, `lastBorrowPoolIndex`, `lastExchangeRate`, or analogous cached fields used directly in health factor or share price calculations
- Identify state transition functions that advance a timestamp (`domainStart`, `lastUpdate`) without first settling outstanding interest or accrued rewards
- Verify that `accrueInterest()` or equivalent is called before any liquidation authorization check
- Check that rebasing token balances are read via `balanceOf()` at call time, not from a stored snapshot
- Confirm TVL or totalAssets values are refreshed before deposit/withdrawal share calculations

**False Positives**

- Protocols where the external system guarantees atomic updates (e.g., a same-block oracle)
- Cached values used only as non-critical metadata (event emission, UI hints) with no impact on fund accounting
- Systems that deliberately use snapshot values for fairness (e.g., TWAP-based pricing)

**Notable Historical Findings**

Morpho contained multiple stale-index findings: Compound's `borrowIndex` was read from Morpho's internal cache rather than from the live cToken, causing health factor and liquidation threshold calculations to understate actual debt. Liquidating a Morpho-Aave position advanced Morpho's internal state without propagating the matching update to Aave, leaving the two systems desynchronized. Mellow Protocol's AaveVault did not update TVL on deposit or withdrawal, so share prices were computed against a stale total. Timeless Finance's `claimYieldAndEnter` accumulated yield against a cached value that did not advance between calls.

**Remediation Notes**

Always call the upstream protocol's `accrueInterest()` or equivalent before reading any derived state (borrow balance, health factor, collateral value). Treat any value obtained from an external protocol as immediately stale and re-fetch it at the point of use. For protocols that cache TVL or totalAssets, invalidate the cache on every deposit, withdrawal, and harvest.

---

### Incorrect State Updates (fv-sol-5)

**Protocol-Specific Preconditions**

- Protocol maintains redundant counters or derived state alongside canonical accounting (e.g., `minipoolCount`, `totalLend`, vote power totals)
- Error, cancellation, or liquidation paths do not update all state that the happy path updates
- Admin parameter changes (fee rates, boost multipliers, thresholds) affect in-flight reward calculations retroactively
- NFT-based position systems do not zero ownership mappings on burn

**Detection Heuristics**

- For every function that increments a counter or accumulator, verify the corresponding decrement exists in every code path that reverses the operation (cancellation, error, emergency exit)
- Check liquidation and slashing handlers for omitted `totalLend`, `totalSupply`, or `minipoolCount` adjustments
- Verify reward parameter setters call `updateReward` before modifying multipliers
- Audit NFT burn functions for dangling `ownerOf` mappings exploitable via index reuse
- Compare state variable sets touched by `create` vs. `cancel`/`error` paths

**False Positives**

- Lazy evaluation patterns where counters are intentionally re-derived on read
- Systems where a missing decrement is bounded to dust and non-exploitable

**Notable Historical Findings**

GoGoPool's `recordStakingError` failed to decrement `minipoolCount`, permanently inflating the count used in reward distribution. Blueberry's `withdrawLend` caused an accounting error in `totalLend` that cascaded into incorrect interest rate calculations. FrankenDAO's `unstake` removed votes using current power rather than the original staked power, enabling vote inflation or permanent power loss depending on whether multipliers increased or decreased after staking. CLOBER's order cancellation did not zero the `ownerOf` mapping, allowing future NFTs minted at the same order index to be stolen.

**Remediation Notes**

For every state variable updated in a forward path, audit all reverse paths (cancel, error, liquidation, emergency). Snapshot the values that need to be reversed at the time of the forward operation (e.g., store `originalVotingPower[tokenId]` at stake time) rather than attempting to recompute them later from potentially changed parameters. Delete all mappings keyed by an ID when that ID is invalidated.

---

### Rounding and Precision Loss (fv-sol-2)

**Protocol-Specific Preconditions**

- Share-to-asset conversions use integer division without explicit rounding direction
- Rounding direction favors the user on withdrawal (round down burns fewer shares) or favors the protocol on deposit (round up gives fewer shares)
- Low-decimal tokens (USDC 6, WBTC 8) interact with 18-decimal reward rates, causing truncation to zero
- Reward accumulator math performs division before multiplication

**Detection Heuristics**

- Check ERC-4626 conversion functions: `previewWithdraw` and `previewRedeem` must round up (shares burned), `previewDeposit` and `previewMint` must round down (assets taken)
- Search for `a * b / c` where the multiplication result can be smaller than `c`
- Look for reward per token calculations involving low-decimal reward tokens divided by large 18-decimal `totalSupply`
- Verify that `rewards[account]` is not cleared when the computed payout rounds to zero
- In reward distribution loops, confirm that the remainder (undistributed dust) is handled

**False Positives**

- Protocols using `Math.mulDiv` with explicit `Math.Rounding.Ceil` or `Math.Rounding.Floor` from OpenZeppelin
- Systems where token amounts are large enough that rounding loss is economically irrelevant
- Fixed-point math libraries (PRBMath, ABDKMath) that handle precision internally

**Notable Historical Findings**

Napier's exchange rate manipulation finding combined rounding errors with first-depositor donation to amplify losses. Surge had two separate findings where `userCollateralRatioMantissa` calculations produced different results depending on operation order. Locke Finance's reward accumulator truncated to zero for small stakers and then cleared their accrued state, permanently losing their rewards. Rubicon's market `buy()` function allowed zero-cost purchases for low-decimal tokens when the spend calculation rounded to zero.

**Remediation Notes**

Use `Math.mulDiv(a, b, c, Math.Rounding.Ceil)` for any conversion that should round against the user (withdrawals, mints that take more assets). Use `Math.Rounding.Floor` for conversions that should round in the protocol's favor (deposits, redeems that give fewer assets). Never clear accrued reward state unless the transfer amount is confirmed non-zero. Add `+ 1` virtual asset and virtual share offsets to share conversion formulas as a combined inflation and rounding fix.

---

### Token Decimal Mismatch (fv-sol-2)

**Protocol-Specific Preconditions**

- Vault or strategy supports multiple tokens with different decimal precisions (USDC=6, WBTC=8, DAI=18)
- Balance aggregation mixes normalized (18-decimal) and raw token amounts in the same expression
- Price oracle returns values in a different decimal basis than token amounts
- LP token valuation code assumes both constituent tokens have the same decimals

**Detection Heuristics**

- Look for arithmetic that sums `balanceOf()` results from tokens with different `decimals()` values without normalization
- Check oracle price arithmetic: confirm the decimal basis of the returned price is accounted for when multiplying by token amounts
- Verify LP valuation functions account for per-token decimal offsets, not a single `POOL_PRECISION`
- Identify any controller or adapter that returns a balance in its own internal denomination that callers assume is in 18 decimals
- Check reward token decimal conversion: ICHI v1 (9 decimals) to v2 (18 decimals) type conversions require multiplying, not dividing

**False Positives**

- Protocols that enforce a strict 18-decimal whitelist and revert on token registration for non-conforming tokens
- Systems that normalize all amounts to a shared internal precision at the boundary and operate uniformly internally

**Notable Historical Findings**

yAxis Vault's `balance()` and `withdraw()` mixed normalized and raw amounts from a controller that returned USDC in 6-decimal basis alongside 18-decimal normalized balances, causing withdrawal amounts to be off by `1e12`. Blueberry's ICHI v2 farming calculation divided by `1e9` when it should have multiplied, delivering `1e18` fewer tokens to users. Notional's Curve vault under-valued or over-valued LP pool tokens for any constituent token with fewer than 18 decimals. Sense Finance's LP oracle required explicit 18-decimal enforcement.

**Remediation Notes**

Normalize all external token amounts to 18 decimals at the earliest point of entry using `amount * 10**(18 - token.decimals())`. Never mix normalized and raw amounts in the same accumulator. When aggregating across multiple tokens in a strategy, normalize each independently. For oracle-derived prices, confirm the returned value's precision matches the expected precision before use in any multiplication.

---

### Slippage, Sandwich, and Frontrunning Attacks (fv-sol-8)

**Protocol-Specific Preconditions**

- Protocol executes token swaps during harvest, compound, or rebalance operations
- `amountOutMinimum` or `min_dy` is set to zero or derived on-chain from the same pool state being manipulated
- Swap transactions are submitted to the public mempool
- `deadline` is set to `block.timestamp`, providing no protection against delayed inclusion

**Detection Heuristics**

- Search for `exactInputSingle`, `exchange`, `swap`, `exchange_underlying` calls with `amountOutMinimum: 0` or `min_dy: 0`
- Check if slippage is computed via an on-chain quoter call in the same transaction as the swap
- Look for keeper/compound functions that execute swaps without a caller-supplied `minAmountOut`
- Verify Balancer/Curve pool deposit/withdrawal functions pass per-token minimum amounts
- Check if `deadline: block.timestamp` is used (equivalent to no deadline)

**False Positives**

- Keeper functions with off-chain computed oracle-derived slippage bounds passed as parameters
- Swaps executing through private mempool relays (still risky but not frontrunnable via public mempool)
- Rebalancing where the swap amount is provably dust-level

**Notable Historical Findings**

Derby Finance had two separate HIGH findings for vault swaps executing with zero slippage protection. Redacted Cartel's `AutoPxGmx.compound` was callable by anyone with no slippage, enabling sandwich attacks on compounding operations. Notional Update had multiple slippage findings including a case where `minTokenAmounts_` was structurally ineffective due to configuration changes. Olympus Update's oracle-update sandwiching allowed an adversary to profit by depositing just before a favorable oracle update and withdrawing before an unfavorable one.

**Remediation Notes**

For user-facing functions, require caller-supplied `minAmountOut` and `deadline` parameters. For automated keeper functions, derive slippage bounds from a manipulation-resistant oracle (Chainlink TWAP) and apply a configurable `MAX_SLIPPAGE_BPS` tolerance. Never compute slippage from the same pool state that will execute the swap. Set `deadline` to `block.timestamp + N` for a meaningful N (e.g., 300 seconds) and revert on expiry.

---

### Reentrancy Vulnerabilities (fv-sol-1)

**Protocol-Specific Preconditions**

- Vault or pool accepts hookable tokens (ERC-777, ERC-721 with `onERC721Received`, ERC-1155)
- State updates (share minting, balance writes, flag flips) occur after external `transfer` or `transferFrom` calls
- No `nonReentrant` modifier on functions that combine external calls with state updates
- Guard patterns (pre/post execution hash checks) use state that can shift during execution

**Detection Heuristics**

- Identify external calls that precede state updates - the canonical violation of Checks-Effects-Interactions
- Check if hookable token standards are used or accepted as deposit tokens
- Look for `balanceOf(address(this))` pre/post measurement patterns without reentrancy guards
- Verify `collectFees` or multi-recipient transfer functions have `nonReentrant`
- Check that guard pre/post execution checks cannot be bypassed by incremented module counts or module additions during the guarded transaction

**False Positives**

- Contracts that interact exclusively with non-hookable tokens (standard ERC-20 with no callback)
- Functions protected by OpenZeppelin `ReentrancyGuard`'s `nonReentrant` modifier
- Code following strict CEI (all state updates complete before any external call)

**Notable Historical Findings**

Buffer Finance's `resolveQueuedTrades` transferred fee refunds before marking trades as non-queued, enabling ERC-777 re-entry to steal funds. Rubicon's `BathToken._deposit` allowed share inflation via re-entry from hookable tokens. Hats Protocol had two separate reentrancy paths enabling signers to add unauthorized safe modules by abusing re-entry during `checkAfterExecution`. Paladin's `MultiMerkleDistributor` could send or withdraw tokens multiple times through an inadvertent re-entry path.

**Remediation Notes**

Follow Checks-Effects-Interactions strictly: write all state changes before making any external call. Add `nonReentrant` to all vault entry points (`deposit`, `withdraw`, `redeem`, `mint`) and fee collection functions. When accepting ERC-777 tokens, recognize that `transferFrom` triggers `tokensToSend` on the sender before the transfer completes, enabling re-entry into any function that has not yet updated state.

---

### Access Control Bypass (fv-sol-4)

**Protocol-Specific Preconditions**

- An access-controlled function calls an internal helper that is also reachable via a separate unprotected path
- Permissionless functions (e.g., `notifyRewardAmount`) internally invoke privilege-requiring helpers (e.g., `_addRewardToken`)
- Cross-chain message handlers validate message content but not the caller (bridge) address
- Public approval or token-transfer functions on the contract itself have no caller restriction

**Detection Heuristics**

- For each internal helper that performs a privileged action, enumerate all external call sites and check each for access control
- Check `notifyRewardAmount` and similar permissionless functions for internal calls to `_addRewardToken` or equivalent
- Verify cross-chain receiver functions check both `msg.sender == trustedBridge` and the source-chain sender
- Search for `approve(token, address)` or similar functions callable by any address on contract-held tokens
- Check that `mintYieldFee`, `rebalance`, and similar protocol-maintenance functions have caller restrictions

**False Positives**

- Intentionally permissionless operations (liquidations, harvests, arbitrage) where any caller is acceptable and outcomes are bounded
- Functions with secondary validation (token whitelist checks) that prevent unauthorized parameter injection even without access control on the outer function

**Notable Historical Findings**

Alchemix's Bribe contract allowed anyone to add arbitrary reward tokens by calling `notifyRewardAmount`, which bypassed the gauge-only restriction on `addRewardToken` by calling `_addRewardToken` directly. PoolTogether's `Vault.mintYieldFee` was callable by any address to mint vault shares to any recipient. Derby Finance's cross-chain rebalance function authenticated the message content but not the bridge address, allowing crafted messages from any caller. Napier Finance had a permissionless path converting users' unclaimed yield without consent.

**Remediation Notes**

Apply access control at the internal helper level or refactor so that permissionless functions only operate on pre-approved tokens, not the token-addition path. For cross-chain receivers, validate both `msg.sender == trustedBridge` and the source-chain address via the bridge's authenticated message metadata. Never expose `approve` or token-management functions as public without access control.

---

### Denial of Service and Griefing (fv-sol-9)

**Protocol-Specific Preconditions**

- Protocol contains loops iterating over arrays that grow without a bounded maximum
- Attacker can cheaply inflate the array (dust delegations, dust NFTs, dust validator registrations)
- Critical path functions (liquidation, withdrawal, settlement) depend on external calls that can revert
- Protocol has a hard cap (e.g., `MAX_DELEGATES = 1024`) that can be filled by an attacker
- Batch operations do not use try-catch, so one failure blocks the entire batch

**Detection Heuristics**

- Search for unbounded `for` loops over user-controlled arrays in withdrawal, liquidation, or settlement functions
- Check for hard limits on delegations, modules, or validators and verify they cannot be exhausted by an attacker at low cost
- Look for critical functions whose only oracle dependency can revert (paused oracle, zero price)
- Verify that batch operations use try-catch or per-item error handling rather than atomically reverting
- Check if a `require(balance == expectedBalance)` check is vulnerable to dust donation causing permanent failure

**False Positives**

- Arrays bounded by a reasonable admin-controlled constant that is not user-influenceable
- Loops where each element's gas cost is trivially small and the array has an enforced maximum
- Systems with alternative execution paths or admin escape hatches for stuck operations

**Notable Historical Findings**

Velodrome Finance's delegation system allowed an attacker to fill `MAX_DELEGATES = 1024` with dust delegations, blocking the victim from receiving further delegations. Sense Finance's AutoRoller could be permanently bricked by a second AutoRoller deployed on the same adapter. Buffer Finance's `resolveQueuedTrades` atomically reverted if any single invalid trade signature was present, blocking resolution of all valid queued trades. Liquid Collective's vesting schedule was permanently broken by an attacker sending 1 wei to an escrow address, causing the `require(balance == totalAmount)` check to permanently fail.

**Remediation Notes**

Replace unbounded array iterations with paginated processing (`start`, `count` parameters). Use try-catch for batch operations. Replace exact-balance comparisons with internally tracked balance accounting that is immune to direct transfers. Impose minimum stake requirements to raise the cost of dust-based griefing. Ensure liquidation and oracle-dependent functions have fallback mechanisms or cached price circuits for oracle outages.

---

### Unsafe Token Handling (fv-sol-6)

**Protocol-Specific Preconditions**

- Protocol accepts arbitrary ERC-20 tokens including fee-on-transfer tokens
- `transferFrom` return values are not checked (raw calls without `SafeERC20`)
- `safeApprove` is called without first resetting allowance to zero (breaks USDT)
- Fee-on-transfer tokens: received amount is assumed to equal the requested transfer amount
- Solmate's `SafeTransferLib` is used without checking that the token address has code

**Detection Heuristics**

- Search for raw `IERC20(token).transfer(...)` and `IERC20(token).approve(...)` calls not wrapped in SafeERC20
- Look for `deposits[msg.sender] += amount` after `transferFrom` without a `balanceBefore / balanceAfter` measurement
- Check all `approve` calls for USDT-style tokens: confirm `approve(0)` precedes any non-zero approval
- Verify Solmate SafeTransferLib usage includes contract-existence validation on the token address
- Look for `allowance[owner][msg.sender] -= amount` that is missing after withdrawal by approved caller

**False Positives**

- Protocols that use OpenZeppelin SafeERC20 throughout and enforce a token whitelist excluding fee-on-transfer tokens
- Systems where the token address is deployed by the protocol itself and known to conform to standard ERC-20

**Notable Historical Findings**

Morpho's USDT mainnet market entered a broken state because the USDT approval path did not reset to zero first. Spartan Protocol had three ERC-20 handling findings in one audit including unchecked return values and allowance bypass. Beanstalk duplicated fees for fee-on-transfer tokens in `LibTransfer::transferFee`. Sushi's `swapCurve` was incompatible with tokens where `approve()` has no return value. Rubicon's `allowance()` function did not limit `withdraw()`, meaning any amount could be extracted regardless of the approved allowance.

**Remediation Notes**

Use OpenZeppelin's `SafeERC20` for all token interactions without exception. For fee-on-transfer token support, measure `balanceAfter - balanceBefore` to determine actual received amounts. For USDT-style approvals, call `safeApprove(spender, 0)` before setting a new non-zero allowance, or use `forceApprove`. Ensure `transferFrom`-based withdrawal functions decrement the caller's allowance after use.

---

### ERC Standard Non-Compliance (fv-sol-5)

**Protocol-Specific Preconditions**

- Contract claims ERC-4626, ERC-5095, ERC-721, or ERC-1155 compliance
- Function parameter usage deviates from the specification (e.g., `mint` transfers `shares` instead of `assets`)
- Rounding direction in ERC-4626 preview functions is opposite to what the spec requires
- Self-transfer handling in custom ERC-20 or ERC-1155 implementations uses cached balances

**Detection Heuristics**

- Compare `mint(shares, receiver)` implementation: must call `asset.transferFrom(msg.sender, address(this), assets)` using the `assets` amount returned by `previewMint`, not the `shares` argument
- Verify `previewWithdraw` rounds up (caller burns more shares) and `previewDeposit` rounds down
- Check ERC-1155 `_transfer` for the self-transfer case: `_balances[id][from] -= amount` followed by `_balances[id][to] += amount` where `from == to` overwrites the deduction
- Confirm `safeTransferFrom` is used rather than `transferFrom` for ERC-721 transfers to arbitrary addresses
- Verify `supportsInterface` returns correct interface IDs

**False Positives**

- Documented intentional deviations with no composability impact
- Contracts that do not claim the affected ERC standard and are not integrated by standard-assuming code

**Notable Historical Findings**

Tribe Finance's ERC-4626 `mint` transferred `shares` instead of `assets` as the deposit amount, allowing users to deposit fewer tokens than the shares they received. Trader Joe's ERC-1155 `_transfer` allowed self-transfers that doubled the caller's balance via cached pre-transfer values. Multiple ERC-721 staking contracts used `transferFrom` rather than `safeTransferFrom`, permanently locking NFTs when sent to contracts without `onERC721Received`. Sense Finance's AutoRoller had rounding directions inconsistent with ERC-4626 specification.

**Remediation Notes**

Implement ERC-4626 conversions using OpenZeppelin's base with explicit `Math.Rounding` arguments on every conversion. Add `if (from == to) return;` as the first line of any `_transfer` implementation. Use `safeTransferFrom` for all ERC-721 transfers where the recipient is not known to be an EOA. Run ERC-4626 property tests (e.g., Trail of Bits' ERC-4626 property test suite) as part of CI.

---

### Replay and Signature Vulnerabilities (fv-sol-4)

**Protocol-Specific Preconditions**

- Protocol uses off-chain signatures for migration, reward claiming, or meta-transactions
- Signed data omits nonce, chain ID, or contract address
- Merkle proof verifications do not track which leaves have been consumed
- `ecrecover` return value of `address(0)` is not checked (succeeds when `owner == address(0)`)

**Detection Heuristics**

- For every `ecrecover` or `ECDSA.recover` call, verify the signed message includes `chainId`, the contract address, and a nonce
- Check Merkle proof claim functions for a `isRedeemed[leaf]` mapping that is set before the claim is processed
- Verify that `permit`-style functions increment a nonce atomically with verification
- Check that `ecrecover` return value is explicitly compared to `address(0)` before use
- Look for signatures that are verified only by deadline - deadline alone does not prevent replay

**False Positives**

- Implementations using OpenZeppelin's `EIP712` with proper domain separator (includes `chainId` and `address(this)`)
- ERC-2612 `permit` with standard `nonces[owner]++` pattern
- Operations that are naturally idempotent and have no economic impact if replayed

**Notable Historical Findings**

Beanstalk's migration function accepted re-used Merkle proofs and re-used signatures without nonce tracking, allowing the same deposit claim to be replayed until the contract was drained. Rigor Protocol had both untyped data signing (raw `keccak256` without EIP-712 domain separator) and a replay path where a builder could call `Community.escrow` repeatedly with the same signature to reduce debt. Biconomy contained a full suite of EIP-712 failures including cross-chain replay, missing nonce, and `ecrecover` returning `address(0)` for uninitialized owners.

**Remediation Notes**

Use OpenZeppelin's `EIP712` base contract. Include `chainId`, `address(this)`, and an incrementing per-address `nonce` in every signed struct hash. For Merkle-based claims, maintain a `mapping(bytes32 => bool) public isRedeemed` and set it to `true` before crediting. Use `ECDSA.recover` from OpenZeppelin which reverts on invalid signatures rather than returning `address(0)`.

---

### Liquidation Logic Flaws (fv-sol-5)

**Protocol-Specific Preconditions**

- Protocol wraps an external lending protocol and must mirror its liquidation authorization logic
- Health factor calculations use stale borrow indexes cached by the wrapper rather than the live protocol value
- Liquidation path requires withdrawing from an external pool that may have zero liquidity
- Deprecated or LTV=0 assets from the underlying protocol are still counted as collateral in the wrapper

**Detection Heuristics**

- Verify that `accrueInterest()` on the underlying protocol is called before any health factor or liquidation threshold check
- Check if assets with `LTV == 0` in the underlying protocol are excluded from collateral valuation in the wrapper
- Test if liquidation can proceed when the underlying pool has zero liquidity for the collateral asset
- Confirm that pausing one function (e.g., repayments) does not leave liquidations enabled for positions that cannot self-remedy
- Verify that deprecated markets still allow liquidation of existing positions

**False Positives**

- Protocols with direct P2P matching that can liquidate without pool liquidity
- Systems where governance can force an index update before a liquidation campaign

**Notable Historical Findings**

Morpho-Compound used a stale `lastBorrowPoolIndex` cache for debt calculations, understating actual debt and preventing legitimate liquidations. Morpho-Aave's LTV=0 handling diverged from Aave's logic, leaving users with non-collateralizable assets still treated as collateral in Morpho. Liquidating a Morpho-Aave position advanced Morpho's state without a matching Aave update, permanently desyncing the two. Blueberry enabled liquidations while repayments were paused, trapping users who could not cure their positions.

**Remediation Notes**

Mirror the underlying protocol's liquidation authorization logic exactly, including e-mode category checks, oracle sentinel authorization, and LTV=0 handling. Always call the underlying `accrueInterest` before reading any derived state. Provide alternative liquidation paths that do not depend on pool liquidity (e.g., P2P collateral seizure). Gate liquidations to be disabled when repayments are also disabled.

---

### Missing Input Validation (fv-sol-5)

**Protocol-Specific Preconditions**

- Setter functions accept `address(0)`, `address(this)`, or out-of-range numeric values without reversion
- Constructors and initializers do not validate critical address or parameter arguments
- Fee parameters have no upper bound (can be set to 100%+ of user funds)
- Arrays that must maintain uniqueness (validator pubkeys, reward tokens) accept duplicates

**Detection Heuristics**

- Search for `function set*(address _x) external onlyOwner` patterns without `require(_x != address(0))`
- Check fee/rate setters for `require(_fee <= MAX_FEE)` bounds
- Verify `initialize` functions validate all address parameters
- Check array-append operations for duplicate prevention where uniqueness is required
- Confirm reward token registration functions cannot register the same token twice

**False Positives**

- `address(0)` used intentionally as a sentinel (e.g., burning to `address(0)`)
- Functions callable only by a multisig with its own off-chain validation layer
- Bounds enforced structurally by the type (e.g., `uint8` fee percentage that cannot exceed 255)

**Notable Historical Findings**

Liquid Collective's `LibOwnable._setAdmin` accepted `address(0)` as the admin, bricking governance. Velodrome Finance accepted duplicate veNFTs in voting checkpoints, inflating voting balances. Morpho's initializer omitted validation for several critical addresses, causing downstream failures when called with zero addresses. Archimedes Finance accepted positions with zero leverage and did not validate parameter precision, leading to fund loss on edge-case inputs.

**Remediation Notes**

Add `require(_addr != address(0), "zero address")` and `require(_addr != address(this), "self")` to all address setters. Bound all fee and rate parameters against a named constant (`MAX_FEE = 1000` for basis points). In initializers, validate every parameter before writing to state. Use a `mapping(bytes32 => bool) registered` guard to prevent duplicate entries in append operations.

---

### ETH Handling and Refund Issues (fv-sol-5)

**Protocol-Specific Preconditions**

- Contract uses `.transfer()` or `.send()` for ETH forwarding (2300 gas stipend fails for smart contract recipients)
- Payable functions that interact with WETH or ETH-denominated swaps do not refund excess `msg.value`
- WETH deposit/withdraw paths wrap a fixed amount but the caller sent more

**Detection Heuristics**

- Search for `payable(x).transfer(amount)` and `x.send(amount)` calls to arbitrary addresses
- Check all `payable` functions for surplus `msg.value` refund after exact-amount operations
- Verify WETH wrapping operations use `{value: exactAmount}` and refund `msg.value - exactAmount`
- Confirm swap functions that return unused ETH do so via `.call{value: ...}("")` with success check

**False Positives**

- `.transfer()` to known EOA addresses where the 2300 gas stipend is sufficient
- Payable functions that consume exactly `msg.value` by design (e.g., exact-ETH deposits)

**Notable Historical Findings**

Morpho's `repayWithETH` wrapped only the `debtAmount` but kept excess ETH in the contract permanently. Sushi's `wrapNative` unwrapped all native tokens regardless of what was requested. Rubicon's FeeWrapper failed to refund ETH from wrapped calls, with an attacker exploiting the retained balance. Multiple protocols used `.transfer()` to send ETH to contract recipients, causing unexpected failures when those recipients had logic in their `receive` functions.

**Remediation Notes**

Replace all `.transfer()` and `.send()` with `.call{value: amount}("")` and verify the return value. After any ETH-involving swap or WETH operation, compute `address(this).balance - preOperationBalance` and refund the surplus to the caller. Use `msg.value` tracking to ensure every wei sent in is either consumed or returned.

---

### Governance and Voting Flaws (fv-sol-5)

**Protocol-Specific Preconditions**

- Total community voting power is tracked as a redundant sum that must be kept in sync with per-user balances
- Delegation changes do not correctly update the total when re-delegating between two non-self addresses
- Unlock time or stake amount is not bounded, enabling artificial voting power inflation
- Proposals can be created or passed before meaningful token distribution occurs

**Detection Heuristics**

- Verify delegation logic updates total only when transitioning between self-delegation and external-delegation (not on re-delegation between two external delegates)
- Check that `unstake` uses the originally recorded voting power, not the current computed value
- Verify `_unlockTime` has an enforced maximum bound (`stakingSettings.maxStakeBonusTime`)
- Confirm `castVote` checks that the caller has non-zero voting power before accepting the vote
- Check that quorum calculations are not manipulable through delegation

**False Positives**

- Snapshot-based voting where power is frozen at proposal creation time
- DAOs with timelock and guardian veto that can block exploited proposals before execution

**Notable Historical Findings**

FrankenDAO had four HIGH governance findings simultaneously: total community voting power updated incorrectly on delegation, `unstake` applying current power rather than original staked power, unbounded `_unlockTime` enabling infinite voting power via `stakedTimeBonus`, and `_unstake` removing votes from `msg.sender` rather than the actual owner. Alchemix's governance accepted proposals below the proposal threshold through a spam path. Olympus DAO allowed any address to pass a proposal before the first VOTES tokens were minted.

**Remediation Notes**

Store `originalVotingPower[tokenId]` at stake time and use it exclusively during unstake. Enforce `unlockTime - block.timestamp <= maxStakeBonusTime`. Update the total community power only when crossing between self-delegated and externally-delegated states. Require `votingPower[msg.sender] > 0` in `castVote`. Use snapshotted balances for quorum calculations to prevent delegation manipulation.

---

### Upgradeable Contract Storage Gap (fv-sol-7)

**Protocol-Specific Preconditions**

- Contract uses a proxy upgrade pattern (UUPS, Transparent, Beacon)
- Base contracts in the inheritance hierarchy define storage variables without a `__gap` array
- Non-upgradeable versions of `Ownable` or other libraries are mixed into upgradeable contracts

**Detection Heuristics**

- Check each base contract in the inheritance chain for a `uint256[N] private __gap` storage reservation
- Verify that `OwnableUpgradeable` is used rather than `Ownable` in proxy-deployed contracts
- Confirm that `Initializable` is the base for all upgradeable contracts and `initialize` is called rather than a constructor
- Check if EIP-7201 namespaced storage is used as an alternative to gap arrays
- Verify that Diamond/EIP-2535 facets use explicit storage position pointers rather than sequential slots

**False Positives**

- Contracts not deployed behind a proxy
- Protocols that have committed to never adding storage variables to base contracts
- Diamond pattern contracts with storage positioned via explicit assembly slots

**Notable Historical Findings**

Notional's vault had a corruptible upgradeability pattern where base contract storage additions would shift all child contract storage slots. Covalent used the non-upgradeable `Ownable` in an upgradeable contract, leaving the owner as `address(0)` after proxy deployment. Biconomy's `SmartAccount` inherited from non-upgradeable contracts while intending to be upgradeable. Rubicon had missing storage gaps across multiple upgradeable base contracts.

**Remediation Notes**

Add `uint256[50] private __gap;` to every base contract in an upgradeable hierarchy, sized to bring each contract's total storage slot count to a round number. Use `OwnableUpgradeable`, `PausableUpgradeable`, and other OpenZeppelin upgradeable variants consistently. Run OpenZeppelin's `upgrades-core` plugin or Hardhat upgrades plugin storage layout diff checks in CI to catch accidental layout changes before deployment.
