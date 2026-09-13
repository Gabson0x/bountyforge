# Synthetic Asset Protocol Security Patterns

> Applies to: synthetic assets, synths, mirror assets, Synthetix-style, collateral-backed synthetic price tracking, debt pool mechanics, synthetic minting and burning

## Protocol Context

Synthetic asset protocols allow users to mint token representations of external price feeds against pooled collateral, creating debt positions denominated in the value of the synthetic rather than the underlying. The debt pool model - where all minters share proportional exposure to the total synthetic supply - means that individual position accounting errors and oracle inaccuracies aggregate across the entire system rather than being isolated to a single user. Price feed manipulation for any collateral or synthetic asset has a multiplied impact because it affects both minting eligibility and debt pool valuation simultaneously.

The architectural dependency on oracle accuracy is more severe than in lending protocols because synthetics have no direct backing asset to recover in a liquidation; the only backstop is the collateral ratio and the ability to burn synthetic tokens at the correct price. This makes rounding errors in debt calculations, incorrect fee accrual in the global debt ledger, and access control gaps on synthetic minting all critical-severity issues. Auction mechanisms used for liquidation must be resistant to griefing that would prevent the protocol from closing undercollateralized positions before collateral value drops further.

## Bug Classes

---

### Access Control and Privilege Escalation (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Functions that modify collateral parameters, oracle addresses, or synthetic minting permissions lack proper access control modifiers. Admin or owner roles have unconstrained privileges allowing immediate fund drainage or oracle replacement without timelocks. Approval or allowance mechanisms in synthetic vault flows can be exploited by unauthorized callers who observe on-chain approvals. NFT-gated collateral withdrawal functions check that the NFT is held but not that `msg.sender` is the rightful depositor. Centralized owner keys can add malicious strategies or adapters that return fabricated data.

**Detection Heuristics**
- Identify all `external` and `public` functions that modify balances, collateral ratios, oracle addresses, or minting permissions and verify they carry appropriate access control modifiers.
- Check for missing ownership verification in collateral NFT withdrawal functions - the function should confirm `msg.sender == depositor[tokenId]`.
- Assess admin powers: can the owner directly drain collateral, swap oracle contracts, or add arbitrary strategy contracts without a timelock?
- Check if approval or allowance is validated before transfers executed on behalf of other users in synthetic minting or redemption flows.
- Review whether critical admin operations require a timelock, multi-sig, or DAO governance delay.

**False Positives**
- The admin is a DAO-controlled timelock with sufficient delay and the risk is publicly documented.
- The function is intentionally permissionless by design, such as a public liquidation call.
- Access control is enforced at a router or proxy layer rather than the implementation contract.
- The function reads state or emits events without modifying balances or critical parameters.

**Notable Historical Findings**
Isomorph allowed any user to withdraw another user's Velo Deposit NFT after the depositor had granted approval to the vault contract, because the withdrawal function verified NFT existence but not that `msg.sender` was the original depositor. Taurus had a finding where a malicious admin could add a strategy contract that reported fabricated collateral valuations, enabling the admin to drain all user collateral. Reality Cards had a `sponsor` function with no access control modifier that allowed any caller to transfer tokens from the treasury to themselves. Velodrome Finance had a finding where a compromised owner could immediately drain the `VotingEscrow` contract of all VELO tokens without any timelock constraint.

**Remediation Notes**
Verify `msg.sender` against the registered owner or approved operator before any collateral withdrawal or position modification. Introduce timelocks for all admin operations that affect oracle addresses, strategy allowlists, collateral parameters, or treasury operations. Emit events with a delay before executing sensitive admin changes to allow monitoring and response. Separate read and write privileges so view functions and non-critical parameter updates do not require the same key as fund-movement functions.

---

### Access Bypass and Rate Limit Circumvention (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Protocol enforces withdrawal caps or cooldown periods per address, but restrictions are tied to the address rather than to the underlying collateral position. Transferring synthetic tokens or collateral receipts to a second address resets or avoids the per-address limit. Cooldown periods enforced at the `withdrawalRequest[msg.sender]` level do not survive token transfers, so a new holder can withdraw immediately. Self-liquidation via alternative code paths such as `closeAll` can bypass invariants enforced on the standard `closePosition` path.

**Detection Heuristics**
- Check if per-address withdrawal limits can be bypassed by splitting across multiple addresses (Sybil attack).
- Verify that token transfers propagate associated cooldown or restriction state to the recipient.
- Look for alternative code paths (liquidation, emergency close, batch close) that skip standard invariant modifiers.
- Check if time-based restrictions survive token transfers or persist only on the requesting address.
- Identify rate limits that do not account for multicall or batch patterns within a single transaction.

**False Positives**
- The rate limit is global rather than per-address, making Sybil bypass irrelevant.
- The alternative bypass path has equivalent restrictions applied via different modifiers.
- The restriction is primarily anti-spam rather than a security-critical invariant.
- Bypassing the limit requires coordinating independent accounts with genuinely separate collateral.

**Notable Historical Findings**
prePO had a `userWithdrawLimitPerPeriod` check that could be bypassed by distributing collateral tokens across multiple addresses, each capable of withdrawing up to the limit independently, effectively multiplying the withdrawal rate by the number of addresses. A separate prePO finding showed the withdrawal delay could be circumvented by transferring collateral tokens before the delay expired, leaving the new holder free to withdraw immediately. Perennial Finance allowed a user to self-liquidate using `closeAll`, which called `_closeMake` and `_closeTake` without the `takerInvariant` modifier that the standard `closePosition` path enforced, enabling positions to be closed in a state that would otherwise be rejected. Inverse Finance's oracle had a two-day low price feature that could be gamed by borrowers to time their repayments at artificially favorable prices.

**Remediation Notes**
Enforce restrictions on the position or collateral receipt rather than only the requesting address. Hook `_beforeTokenTransfer` to block transfers during active withdrawal windows or to transfer the cooldown state to the recipient. Apply identical invariant checks on all code paths that close or modify positions, including liquidation, emergency, and batch variants. Where self-liquidation is permitted, confirm it does not exempt the user from invariants designed to protect protocol solvency.

---

### Auction Mechanism Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol uses Dutch auctions for liquidations or collateral sales where the price decays over time and can fall below the protocol's break-even threshold, creating bad debt. Auction settlement and new auction creation are coupled in a single transaction using try-catch, making the creation step vulnerable to gas manipulation via EIP-150. First liquidity provider in a stable AMM-style auction pool can set imbalanced initial reserves that make the invariant value near zero, blocking all subsequent swaps.

**Detection Heuristics**
- Check if auction settlement triggers new auction creation in the same transaction with a bare `catch` block that pauses the protocol on any error including out-of-gas.
- Verify auction price decay formulas enforce a minimum floor price that covers the protocol's liquidation break-even.
- Look for first-depositor advantages in AMM-style auction pools where the initial invariant value can be set near zero.
- Check if auction timing parameters are dependent on external state that an attacker can manipulate.
- Verify that auction reserve formulas account for all accumulated debt and fees before pricing collateral.

**False Positives**
- The protocol has an insurance fund or admin restart mechanism that covers bad debt from below-floor auctions.
- The gas manipulation attack cost exceeds the value of forcing the protocol into a paused state.
- First-depositor concern is mitigated by a bootstrapping phase with restricted access.
- The auction is designed to intentionally reach zero (Dutch auction to completion is the intended behavior).

**Notable Historical Findings**
Nouns Builder's `_createAuction` used a bare `catch` block that called `_pause()` on any error from `token.mint()`, meaning an attacker could restrict the forwarded gas via EIP-150's 63/64 rule so the mint call ran out of gas while leaving enough gas for `_pause()` to succeed, permanently halting auctions. Ajna's liquidation auction price decay formula could fall below the collateral's break-even value before any bidder participated, leaving the protocol with bad debt on every under-bid liquidation. Velodrome Finance's first liquidity provider for stable pairs could deposit imbalanced reserves so the `x^3*y + y^3*x` invariant value was effectively zero, causing all subsequent swaps in that pool to revert. A separate Nouns Builder audit found a precision error in `_computeTotalRewards` that could permanently brick auction reward computation.

**Remediation Notes**
In try-catch auction creation, inspect the specific error selector in the catch block and only pause on expected error types (e.g., `NO_METADATA`); treat unrecognized errors including out-of-gas as reverts rather than valid pause triggers. Enforce a minimum auction price equal to or above the protocol's liquidation break-even threshold to prevent bad debt creation. Require a minimum invariant value for stable pair initial deposits to prevent zero-k pool manipulation.

---

### Denial of Service and Griefing (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Contract iterates over arrays or counters that grow without bound over the protocol lifetime, eventually exceeding block gas limits. External calls to plugins, adapters, or market contracts within loops allow a single broken integration to block the entire deposit or withdrawal flow. Try-catch blocks with bare catch handlers can be manipulated via EIP-150 gas restriction to trigger the catch branch's state changes without the intended operation completing. Dust token deposits or refunds can cause arithmetic to revert in functions shared by all users.

**Detection Heuristics**
- Identify loops over arrays or sequential counters that grow without a hard cap and verify gas usage stays within safe bounds.
- Check for `try/catch` blocks where the catch branch writes state (pause, revert mode, counter increment) rather than simply emitting an event.
- Look for batch operations where a single item's failure reverts the entire batch rather than being skipped or queued.
- Search for functions where an attacker can force a dust send that triggers an arithmetic underflow or revert for all subsequent callers.
- Identify external call dependencies on third-party contracts that can be paused or broken, where no fallback or skip logic exists.

**False Positives**
- The array has a hard cap that keeps gas usage within safe block limits for the foreseeable protocol lifetime.
- The protocol has an admin function to skip or remove problematic queue entries.
- The denial of service is temporary and self-resolving (for example, a Chainlink oracle that resumes after downtime).
- The gas cost of mounting the attack exceeds the value that can be extracted or the damage caused.

**Notable Historical Findings**
Bond Protocol's `BondAggregator.liveMarketsBy` iterated over an unbounded `marketCounter` twice in a single view function, a pattern that would eventually hit block gas limits as the number of markets grew. Union Finance had multiple findings involving unbounded iteration: the `getFrozenInfo` vouches array could exceed gas limits, the priority withdrawal sequence grew infinitely, and a single broken money market adapter caused all deposits and withdrawals to fail. Velodrome Finance's `depositManaged` could be permanently blocked by delegating tokens to `MAX_DELEGATES = 1024`, after which any further delegation caused the function to run out of gas. VTVL had a permanent freeze vulnerability caused by an arithmetic overflow in `_baseVestedAmount` that blocked all vesting operations for affected recipients once the overflow condition was reached.

**Remediation Notes**
Paginate all iterations over protocol-level arrays with explicit start and end parameters. Remove or skip broken adapters and plugins atomically and revoke their approvals on removal. In try-catch patterns that produce state changes on failure, inspect the specific error type and treat unexpected errors (including out-of-gas from the 63/64 gas limitation) as hard reverts rather than handled failures. Enforce hard caps on delegate counts and other per-address arrays that feed into unbounded loops.

---

### First Depositor Vault Share Manipulation (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Synthetic vault or collateral pool uses `totalAssets / totalSupply` share pricing without an initial anchor. The first depositor mints shares at a 1:1 ratio, then donates tokens directly to the vault contract to inflate `totalAssets`, making the share price expensive enough that subsequent depositors receive zero shares due to integer division rounding, losing their entire deposit. ERC-4626 vaults used for synthetic collateral management that lack `_decimalsOffset()` are directly vulnerable to this pattern.

**Detection Heuristics**
- Check if the vault mints dead shares or enforces a minimum initial deposit at initialization.
- Verify `convertToShares` handles `totalSupply == 0` with a minimum ratio that prevents the attack.
- Look for ERC-4626 vaults where `previewDeposit` can return zero shares for non-zero assets.
- Check if tokens can be donated directly to the vault contract and reflected in `totalAssets()` without minting shares.
- Verify vault initialization sequences lock minimum liquidity before opening to external deposits.

**False Positives**
- The vault mints dead shares or requires a minimum initial deposit that makes the donation attack economically infeasible.
- The vault applies OpenZeppelin's virtual share offset via `_decimalsOffset()`.
- Direct token donations are not reflected in `totalAssets()` because assets are tracked via internal accounting rather than balance reads.
- The vault only accepts deposits from a trusted router contract that controls first deposit behavior.

**Notable Historical Findings**
Mycelium's tracker vault allowed an attacker to manipulate `pricePerShare` by depositing 1 wei, then donating tokens to inflate the share price so future depositors received zero shares and the attacker could redeem at a profit. Perennial Finance's `BalancedVault` had a similar early depositor exchange rate manipulation finding. Sense Finance's public vault finding showed the initial depositor could set the price-per-share value to a level that caused future depositors to lose funds. Timeswap's first liquidity provider received disproportionate short tokens due to increased duration in the initial period, providing a first-mover extraction advantage.

**Remediation Notes**
Mint a fixed quantity of dead shares (e.g., `1000`) to `address(1)` on the first deposit and deduct them from the depositor's share allocation. Alternatively, apply a `_decimalsOffset()` of at least 6 in ERC-4626 implementations, which requires an attacker to donate `1e6` times the victim's deposit to reduce them to zero shares. Where internal asset accounting is used instead of raw balance reads, confirm the accounting path prevents donation inflation.

---

### Frontrunning and MEV Exploitation (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
Two-step operations where an approval or authorization transaction is separate from the protected action allow frontrunners to intercept the asset between steps. Reward claims, yield harvests, and accumulated fees can be frontrun by the current owner before a pending transfer completes. Deployment and initialization sequences that set access controls in a transaction separate from contract creation create a window for unauthorized minting or configuration. Liquidation transactions visible in the mempool reveal profitable positions allowing competing liquidators to race.

**Detection Heuristics**
- Identify two-step operations where approval or setup and execution appear in separate transactions with no commitment binding them together.
- Check if reward claims, yield harvests, or fee collections can be triggered by the current token holder before a sale or transfer completes.
- Look for deployment or initialization sequences where access controls, hooks, or price parameters are set after contract creation in a separate transaction.
- Search for liquidation functions whose parameters are fully visible in the mempool and lack any MEV protection.
- Verify that parameter changes such as fees, prices, or oracle sources cannot be sandwiched for profit.

**False Positives**
- Operations use a commit-reveal scheme or are submitted through a private mempool.
- The frontrunning profit is smaller than the gas cost of the attack.
- The protocol operates on an L2 with a centralized sequencer that prevents traditional mempool frontrunning.
- The two-step process has a timelock or authentication that prevents unauthorized interception between steps.

**Notable Historical Findings**
Ajna's CryptoPunks deposit flow required the user to first offer the punk for sale to the pool address at zero price in one transaction, then call `depositPunk` in a second transaction, creating a window where any observer could buy the punk for zero and take the user's position. Wenwin's lottery allowed the seller of a winning ticket to frontrun the buyer's purchase by claiming the reward between the sale agreement and the transfer settlement, leaving the buyer with a worthless ticket. prePO deployed `PrePOMarket` without setting the `mintHook` in the constructor, leaving a window between deployment and hook assignment where anyone could mint unrestricted Long and Short tokens. Abracadabra Money's `create()` factory was vulnerable to reorg attacks where the deployed market address could be predicted and front-deployed with different parameters.

**Remediation Notes**
Combine approval and action into a single atomic transaction wherever possible. For NFT-gated protocols that cannot atomically transfer and act, use a dedicated wrapper or intermediary that performs both steps atomically. Auto-claim rewards during `_beforeTokenTransfer` so that pending rewards are settled before ownership changes. Set all access controls and hooks in the constructor rather than in a post-deployment initialization transaction. For liquidation systems on public chains, consider using commit-reveal or batch auctions to reduce MEV extraction.

---

### Reward Distribution and Staking Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Reward accumulation divides by `totalStaked` or `totalSupply` which can be zero, causing rewards emitted during empty periods to be permanently lost. Epoch boundary calculations use off-by-one errors that read the next epoch's checkpoint instead of the current epoch's final state. Reward multipliers are based on the duration since `lastUpdated` which is reset by re-borrowing or re-staking, allowing users to game the multiplier without providing genuine economic value. Users can claim rewards from future epochs that have not yet been finalized.

**Detection Heuristics**
- Check `rewardPerToken()` behavior when `totalSupply == 0`: rewards should pause accumulation or be held, not emitted without distribution.
- Look for epoch or period boundary calculations with potential off-by-one errors, specifically checking whether `_currTs + DURATION` reads into the current or next epoch's data.
- Verify reward multipliers cannot be reset by cycling positions: re-staking, re-borrowing, or re-depositing should not provide a fresh multiplier.
- Check if users can call claim functions for future epochs that have not yet been finalized.
- Look for reward accumulation that uses stale `lastUpdated` timestamps based on actions the user can trigger at will.

**False Positives**
- Protocol intentionally burns unclaimed rewards as part of its documented tokenomics model.
- Lost rewards during zero-supply periods are automatically redistributed in the next active period.
- Multiplier gaming requires locking capital at a cost that exceeds the incremental reward benefit.
- Epoch boundary differences result in negligible reward discrepancies below the protocol's minimum unit.

**Notable Historical Findings**
Velodrome Finance had a high-severity finding where `RewardDistributor` cached `totalSupply` at the start of epoch calculations, causing reward amounts to be computed incorrectly for all stakers whenever supply changed during the period. Union Finance had multiple staking reward findings: stakers could gather maximal multipliers regardless of whether borrowers were overdue by exploiting a stale frozen calculation, rewards were lost as `updateLocked` only processed the first active vouch array before stopping, and a staker could maximize UNION reward issuance by cycling deposits without providing real credit. Ajna's rewards manager did not delete old bucket snapshot info on unstaking, allowing users to claim rewards for future epochs that had not yet been finalized. Abracadabra Money's `LockingMultiRewards` had permanent yield loss due to precision loss in per-token reward accounting.

**Remediation Notes**
Gate reward accumulation behind a `totalSupply > 0` check; hold accumulated rewards in a separate variable during zero-supply periods and release them when stakers return. Use independent per-epoch snapshots rather than shared running totals that can be desynchronized. Invalidate multiplier state on any position reset action such as re-stake or re-borrow. Prevent reward claims for epochs that have not yet been finalized by checking that the epoch's end timestamp has passed and the snapshot is complete.

---

### Rounding and Precision Loss (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Contract performs division before multiplication in reward or price calculations, causing intermediate truncation. Synthetic minting, debt issuance, and collateral valuation use inconsistent rounding directions across paired functions. Small input amounts produce zero shares due to floor division, and repeated small transactions can extract value by paying zero fees. Liquidation arithmetic truncates collateral seizure, leaving dust bad debt that accumulates over time and degrades pool health.

**Detection Heuristics**
- Search for division operations followed by multiplication in the same computation path, particularly in reward rate and collateral ratio calculations.
- Check if `mulDiv` vs `mulDivUp` rounding direction is consistent across paired operations: deposits round down shares, withdrawals round up assets.
- Look for intermediate calculations that could round to zero for small but economically valid inputs.
- Verify that fee calculations cannot be avoided by splitting large operations into many small ones where each rounds fees to zero.
- Identify mismatched precision between Chainlink price feeds (8 decimals) and token amounts (18 decimals) in collateral valuation.

**False Positives**
- Precision loss is bounded to 1 wei per operation and accumulation is bounded by protocol constraints.
- The protocol explicitly documents and accepts a specific rounding direction with a stated rationale.
- Rounding consistently favors the protocol over the user, which is the safe default.
- Inputs are constrained to minimum sizes where precision loss is negligible.

**Notable Historical Findings**
Bond Protocol had multiple rounding issues: market price used `mulDivUp` in one calculation path but `mulDiv` in a related internal function, causing inconsistent pricing that borrowers could exploit for better terms. Ajna's liquidation arithmetic truncated the seized collateral amount when the borrower's collateral was fractional, allowing `take` to proceed with the full debt but less collateral, worsening the protocol's position. Abracadabra Money's `MagicLP` had a high-severity finding where a rounding error in the invariant calculation could be amplified by an attacker to break the `I` invariant, enabling malicious arbitrage. Fractional's migration function had severe precision loss when `_newFractionSupply` was set to a very small value, causing users to lose entire fractions to rounding.

**Remediation Notes**
Always multiply before dividing to preserve precision at intermediate steps. Use consistent rounding direction across paired functions: `previewDeposit` rounds down shares, `previewWithdraw` rounds up assets, `convertToShares` rounds down, `convertToAssets` rounds down. Enforce minimum transaction sizes that guarantee at least 1 unit of fee is collected. In liquidation paths, round seized collateral up (more collateral per debt unit) to ensure the protocol's position improves after every liquidation.

---

### Token Decimal Assumptions (ref: fv-sol-3)

**Protocol-Specific Preconditions**
Protocol hardcodes 18 decimals or `WAD` (1e18) in collateral valuation, synthetic issuance, and debt calculations while interacting with tokens of 6 decimals (USDC), 8 decimals (WBTC), or 8-decimal Chainlink price feeds. Fixed-point math libraries assume matching precision across all token pairs in LP pricing functions. Minimum amount thresholds are expressed as absolute values that represent wildly different economic quantities depending on the token's decimal count.

**Detection Heuristics**
- Search for hardcoded `1e18`, `10**18`, or `WAD` in arithmetic involving external token amounts without a prior decimal normalization step.
- Check if `decimals()` is called and applied for normalization in every price and value calculation.
- Verify that Chainlink price feed decimals (typically 8) are explicitly accounted for when combining with token amounts in collateral ratio calculations.
- Look for fixed minimum amounts or thresholds that do not scale with token decimals.
- Identify LP token pricing functions that assume both underlying tokens have equal decimal precision.

**False Positives**
- Protocol explicitly supports only 18-decimal tokens and enforces this at token registration with a `require(decimals() == 18)` check.
- Decimal normalization is handled by an oracle wrapper or adapter layer that standardizes all values before they reach the protocol.
- The token whitelist only includes tokens with matching decimal counts for the specific use case.
- The hardcoded value is mathematically correct for the specific token pair being used in that function.

**Notable Historical Findings**
Taurus assumed all collateral tokens had 18 decimals in its core collateral valuation function, causing a high-severity undercollateralization bug when USDC or WBTC were used as collateral because the value calculation was off by factors of `1e12` or `1e10` respectively. Isomorph's `DepositReceipt` contracts broke when WBTC LP positions were used because the contract used WAD for both tokens in the LP pair value calculation, severely mispricing the 8-decimal token. Sense Finance's LP oracle needed to either enforce 18 decimals for the underlying token or use decimal-flexible fixed-point math; both paths produced incorrect valuations for non-18-decimal tokens. Inverse Finance's oracle assumed Chainlink feed decimals would always be at most 18, failing when a feed returned 20 decimals.

**Remediation Notes**
Read `IERC20Metadata(token).decimals()` at the point of every price and collateral calculation and normalize to a common base precision (18 decimals) before arithmetic. Read the Chainlink aggregator's `decimals()` method explicitly and incorporate it into every price feed read. Replace hardcoded `WAD` in LP pricing with `10 ** token.decimals()` per token. Enforce decimal assumptions at token registration time with an explicit check that reverts if the token does not meet the protocol's supported decimal range.

---

### Unsafe ERC-20 Token Handling (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Protocol uses bare `transfer()` or `transferFrom()` instead of `safeTransfer()` and `safeTransferFrom()`, failing silently when the token returns `false` on failure (USDT on non-Ethereum chains, BNB, OMG). Fee-on-transfer tokens are credited at the nominal transfer amount rather than the measured received amount. ETH is forwarded using `.send()` or `.transfer()` which impose a 2300 gas stipend that fails for contract recipients with non-trivial `receive` logic. ERC-777 tokens accepted as synthetic collateral trigger `tokensReceived` hooks that can reenter state-modifying functions.

**Detection Heuristics**
- Search for `transfer()` and `transferFrom()` on ERC-20 tokens without wrapping in `safeTransfer` or checking the boolean return value.
- Identify tokens in the supported asset list that are known to return `false` on failure rather than reverting.
- Check if `amount` is used directly for accounting after transfers without a balance-before/balance-after measurement.
- Look for `.send()` or `.transfer()` for ETH delivery instead of `.call{value: amount}("")`.
- Check for `approve()` calls on tokens that require setting allowance to zero before a new value (USDT on Ethereum).

**False Positives**
- Protocol only supports a specific token known to revert on failure such as DAI or WETH.
- OpenZeppelin or Solmate `SafeERC20` is already used consistently across all transfer paths.
- The token whitelist explicitly excludes fee-on-transfer and rebasing tokens with enforced documentation.
- The ETH recipient is always an EOA or a known contract that does not exceed the gas stipend.

**Notable Historical Findings**
Inverse Finance's repayment flow used bare `transfer` without checking the return value, allowing a failed transfer to proceed silently and leave the borrower's debt unchanged while the protocol believed the repayment had occurred. Blur Exchange had a Yul-level `call` whose return value was not checked, enabling fund loss when the call failed. OpenQ had multiple unsafe ERC-20 issues including a high-severity finding where bounties could be broken by funding them with malicious ERC-20 tokens that implemented destructive transfer hooks. Union Finance's `AssetManager.withdraw` did not return false on failure, causing the asset manager's retry logic to treat failed withdrawals as successful and proceed without funds.

**Remediation Notes**
Use OpenZeppelin `SafeERC20` or Solmate's `safeTransfer` for all ERC-20 token interactions without exception. Measure actual received amounts using balance-before/balance-after for any token that may have transfer fees. Use low-level `.call{value: amount}("")` for all ETH transfers and check the boolean success return. For tokens that require zero-allowance before approval (USDT), use the pattern `safeApprove(0); safeApprove(amount)` or use `safeIncreaseAllowance`.

---

### Unsafe Type Casting and Integer Overflow (ref: fv-sol-3)

**Protocol-Specific Preconditions**
Contract explicitly casts values to narrower integer types (`uint16`, `uint96`, `uint128`) without range checking, silently truncating reward values or staking amounts. User-supplied expiration timestamps accept `type(uint256).max` as input, which cannot be safely stored in smaller timestamp types used by other protocol components. Solidity 0.8 overflow protection is bypassed by `unchecked` blocks in hot paths where adversarial inputs are possible.

**Detection Heuristics**
- Search for explicit narrowing casts: `uint16(x)`, `uint96(x)`, `uint128(x)`, `int128(x)` - verify the value is range-checked before casting.
- Check if `unchecked` blocks contain arithmetic that could overflow or underflow with adversarial inputs that reach that code path.
- Look for sentinel values like `type(uint256).max` for expiration or amount fields that could cause unexpected behavior when passed to functions using smaller integer types.
- Verify that timestamp values stored in smaller types (uint32, uint40, uint48) will not overflow within the realistic operational lifetime of the protocol.
- Identify where `SafeCast` is used and verify it is applied consistently wherever downcasting occurs throughout the codebase.

**False Positives**
- The input is validated to be within the target type's range before the cast is performed.
- OpenZeppelin `SafeCast` is used at all narrowing cast sites, which reverts on overflow.
- The `unchecked` block contains operations that are mathematically proven safe by invariants maintained elsewhere.
- The timestamp or amount range is naturally bounded by other protocol constraints that prevent overflow.

**Notable Historical Findings**
Wenwin's reward packing function cast each prize value to `uint16` by dividing by a divisor and truncating without checking if the divided value exceeded `65535`, causing high prizes to silently wrap to small values that misdistributed winnings. OpenQ had a high-severity finding where a user could deposit with `_expiration = type(uint256).max`, locking their deposit permanently because the maximum value was accepted without a cap check. VTVL had a permanent vesting freeze caused by an overflow in `_baseVestedAmount` that was reachable under certain vesting schedule configurations, preventing any vesting operations for affected recipients. Velodrome Finance's `RewardsDistributor` had an unsafe cast from a large `uint256` to a smaller type that produced an underflow, corrupting `veForAt` balance calculations.

**Remediation Notes**
Use OpenZeppelin `SafeCast` for all narrowing casts rather than relying on implicit or explicit truncation. Enforce maximum bounds on user-supplied expiration timestamps using `require(expiration <= block.timestamp + MAX_DURATION)`. Replace `unchecked` arithmetic in reward and vesting calculations unless the safety proof is explicit and documented inline. Store timestamps in types sized appropriately for the protocol's expected operational lifetime with margin.

---

### Unchecked External Calls and Untrusted Contracts (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Protocol integrates with external adapters, plugins, or oracle contracts that can be upgraded, paused, or become malicious. External call return values are not checked, allowing silent failures to corrupt accounting state. Protocol accepts arbitrary contract addresses as adapter or oracle parameters without verification against a vetted registry. `delegatecall` is used against user-supplied or upgradeable targets that can modify vault storage layout.

**Detection Heuristics**
- Search for external calls where the return value is not stored or checked against expected success states.
- Identify `delegatecall` to addresses that are not hardcoded or verified against a whitelist or registry.
- Look for plugin or adapter loops where a single external call failure reverts the entire operation rather than being isolated.
- Check if adapter or oracle addresses can be changed by admin to arbitrary values without a timelock or registry check.
- Verify that removed adapters have their token approvals revoked to prevent continued access.
- Look for uncached `decimals()` calls on untrusted ERC-20 tokens whose return value can change between calls.

**False Positives**
- The external contract is immutable, audited, and its address is hardcoded in the implementation.
- External call failure is the intended behavior, such as an optional post-hook that the protocol can function without.
- The admin controlling adapter addresses is a timelock with sufficient delay for monitoring and intervention.
- The `delegatecall` target is restricted to a verified implementation registry with immutable entries.

**Notable Historical Findings**
Mycelium's vault had a finding where a single broken or paused plugin caused all `deposit()` and `withdraw()` operations to fail for all users because the plugin call was in a loop without any error isolation. Sense Finance's adapter interaction allowed calls to transient or unverified external contracts, and the `GClaimManager` was missing reentrancy guards around external claims. Union Finance's `AssetManager` would revert all `deposit`, `withdraw`, and `rebalance` operations when any one of its money market adapters failed, and adapters that were removed kept their token approvals active. Blur Exchange's low-level Yul `call` did not check the return value, silently failing transfers and producing incorrect state.

**Remediation Notes**
Check all external call return values and revert or handle the error explicitly. Wrap individual plugin and adapter calls in try-catch and continue to the next available integration rather than reverting the entire operation. Require that all adapter addresses are validated against an approved registry before interaction. Revoke token approvals when removing or replacing adapters. Cache `decimals()` return values from untrusted tokens at the time of token registration rather than calling them on every operation.
