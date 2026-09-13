# Bridge and Cross-Chain Security Patterns

> Applies to: asset bridges, token bridges, cross-chain message passing, LayerZero integrations, Wormhole integrations, Axelar integrations, lock-and-mint bridges, burn-and-mint bridges, optimistic bridges

## Protocol Context

Bridges are architecturally unique because correctness depends on two independent execution environments that cannot atomically read each other's state: a lock or burn on the source chain must be faithfully reflected as a mint or release on the destination chain with no shared transaction context to enforce atomicity. The trust model extends beyond on-chain code to off-chain relayers, oracle sets, or validator committees whose compromise can authorize fraudulent minting without corresponding locking. Every cross-chain message carries a distinct attack surface - replay across chains, payload tampering during transmission, and gas griefing on the destination side - that has no equivalent in single-chain protocols.

## Bug Classes

### Access Control Misconfiguration (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Critical bridge functions (router recipient setter, fee recipient, mirror connector address) lack access control modifiers or use one-time-set patterns vulnerable to front-running
- Privileged roles such as admin or operator can unilaterally change bridge parameters (acceptance delay, stable swap address, flow rate) or drain router liquidity
- Ownership renouncement or transfer to the zero address removes the only actor capable of performing emergency actions, permanently bricking bridge operations
- Role assignment for multisig participants lacks a removal path, leaving compromised signers permanently privileged

**Detection Heuristics**
1. Enumerate every `external` and `public` function that writes state; verify each has an appropriate access control modifier
2. Check one-time-set patterns for front-run exposure: any setter that checks `if (value == address(0))` rather than `if (msg.sender == deployer)` is vulnerable
3. Confirm every privileged role can be revoked and that revocation does not orphan protocol functionality
4. Verify ownership transfer uses the two-step nominate-then-accept pattern
5. Audit diamond facets: `diamondCut` allowing re-execution of already-applied cuts is a distinct access control failure

**False Positives**
- Intentionally permissionless functions (public liquidations, permissionless relayer calls)
- Admin functions protected by a multi-sig with a timelock
- Setters that affect only the calling account's own state

**Notable Historical Findings**
In Connext audits, multiple findings documented that the `WatcherManager`, router recipient, and `acceptanceDelay` could be configured by unauthorized actors or configured only once with no removal path, leaving the bridge in an irreparable state after a misconfiguration. The Decent bridge allowed anyone to overwrite the router address in the `DcntEth` contract, enabling immediate fund theft at zero cost. Axelar's multisig implementation allowed the same proposal to be executed repeatedly due to missing deduplication, and a deployer wallet retained the ability to spoof validated senders after an ownership transfer completed.

**Remediation Notes**
One-time-set bridge parameters must be protected by the deployer address stored at construction time, not by checking whether the parameter is already populated. All bridge admin roles must support removal, and any removal path must be tested for cascading impact on live routes. Ownership transfers must use the nominate-and-accept pattern so that a mis-typed address does not permanently lock administration.

---

### Reentrancy (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Token transfer callbacks (ERC-777 `tokensReceived`, ERC-721 `safeTransfer`, native ETH `receive`) fire before bridge accounting is finalized
- Bridge executor or router contracts perform external calls to user-specified targets that can re-enter the same function
- Read-only reentrancy: a bridge pricing function reads pool balances (Balancer, Uniswap) during a vault callback, yielding a stale or manipulated price
- Gnosis Safe module hooks (`checkTransaction`, `checkAfterExecution`) can be re-entered before the module's own state is consistent

**Detection Heuristics**
1. Identify all functions that make external calls; confirm state updates precede the call (Checks-Effects-Interactions)
2. Flag any function lacking `nonReentrant` that transfers tokens or calls user-supplied targets
3. Check for ERC-777 token support and whether `tokensReceived` hooks can re-enter deposit or withdraw paths
4. Identify view functions that query on-chain AMM state; determine whether that state can be manipulated inside a callback from the same transaction

**False Positives**
- External calls to immutable, trusted contracts with no callbacks
- Functions where all state updates provably precede external calls and no re-entrant path exists back to the function

**Notable Historical Findings**
Axelar ITS allowed `expressReceiveToken` to be re-entered via ERC-777 token hooks, enabling double-minting of bridged tokens without a corresponding lock on the source side. The Connext Executor's forwarding of user-supplied calldata could re-enter bridge logic before the delivered tokens were marked as claimed. Balancer read-only reentrancy was demonstrated in the Cron Finance audit, where a pricing function could be called during a Balancer vault callback, returning pool balances that were mid-modification.

**Remediation Notes**
Bridge executor and router contracts that forward arbitrary calldata must apply `nonReentrant` regardless of apparent CEI compliance, because the payload target is untrusted. Contracts pricing assets via AMM pool balances should call the Balancer vault reentrancy guard or use a TWAP source that does not read live pool state.

---

### Arithmetic and Precision Errors (ref: fv-sol-2, fv-sol-3)

**Protocol-Specific Preconditions**
- Bridges move tokens between chains with differing decimal precision (e.g., USDC uses 6 decimals on Ethereum, 18 on some L2 deployments); arithmetic that assumes a fixed decimal count silently misprices amounts
- Fee and exchange rate calculations apply division before multiplication, creating compounding precision loss at scale
- `unchecked` arithmetic in packed storage or reward accumulators can silently overflow between claims, causing permanent fund loss
- Collateral valuations compare amounts denominated in different decimal bases without normalization
- Rounding direction is inconsistent with the protocol safety invariant; rounding in the user's favor on withdrawals drains the vault over time

**Detection Heuristics**
1. Check every division that precedes a multiplication in fee, reward, or exchange rate calculations
2. Audit all `unchecked` blocks for overflow potential when values originate from user input or cross-chain messages
3. Verify that token arithmetic normalizes to a common decimal base before comparison or aggregation
4. Confirm oracle price scaling (typically 1e8 for Chainlink) is applied consistently relative to token decimals
5. Confirm rounding direction: shares-to-assets conversions should round against the redeemer; assets-to-shares should round against the depositor

**False Positives**
- `unchecked` blocks used for counter increments where overflow is geometrically impossible given supply constraints
- Precision loss documented as accepted and economically negligible at the protocol's minimum transfer size
- Intentional rounding direction documented in the specification

**Notable Historical Findings**
Connext audits found that `_slippageTol` was evaluated on incomparable scales because it was not adjusted for decimal differences between paired tokens. Axelar ITS had completely broken balance tracking for tokens with different decimal counts on different chains, leading to systematic under-crediting on destination chains. In the Blueberry audit, `IchiLpOracle` returned inflated prices due to a decimal precision error in the price calculation path, causing affected collateral to be valued far above market rate.

**Remediation Notes**
Bridge code that interacts with tokens on multiple chains must never assume a fixed decimal count. All cross-chain accounting should normalize amounts to an internal representation (18-decimal WAD) immediately upon receipt and denormalize only when transferring to the destination token contract. Use `Math.mulDiv` with an explicit rounding direction constant rather than bare division.

---

### Unchecked Return Values (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Bridge contracts use low-level `.call()` to forward execution or send ETH without asserting the returned success flag
- ERC20 `transfer` and `transferFrom` are called directly without `SafeERC20`, silently succeeding on tokens that return `false`
- A `require(success)` check appears after a `return` statement, making it dead code
- External protocol calls (staking, yield vault withdrawals) return a boolean that is discarded

**Detection Heuristics**
1. Grep for `.call{value:` patterns; confirm every returned `bool` is asserted in a `require` or conditional
2. Find all `IERC20(token).transfer(` and `IERC20(token).transferFrom(` usages; flag any not wrapped in `SafeERC20`
3. Look for `return` statements followed by `require` statements in the same function scope
4. Audit protocol-specific external calls (staking, vault deposit/withdraw) for discarded boolean returns

**False Positives**
- Contracts using `SafeERC20` throughout, which internalizes return value handling
- Fire-and-forget refund attempts where failure is intentionally non-blocking and documented

**Notable Historical Findings**
LI.FI had a finding where the return value of a low-level `.call()` was never checked in the receiver contract, allowing a failed bridge execution to silently pass without delivering funds. In the Sturdy audit, the success check for an ETH withdrawal was placed after a `return` statement and was therefore unreachable, meaning a failed transfer would be treated as successful. Notional finance audits found that `auraBooster.deposit` and `auraRewardPool.withdrawAndUnwrap` returned booleans that were never inspected, leaving failed staking operations undetected and bridge accounting incorrect.

**Remediation Notes**
Every `.call()` that sends ETH in a bridge context must check the success flag; failed delivery should emit an event and queue a retry rather than silently proceeding. Use `SafeERC20` without exception for all ERC20 interactions in bridge contracts, which must handle arbitrary tokens including those that return `false` rather than reverting.

---

### Slippage and Price Manipulation (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Destination-chain swap legs in bridge transactions do not accept a user-specified `minAmountOut`, forcing users to accept any resulting price
- Cross-chain swap calls use `block.timestamp` as the deadline, which is always satisfied and provides no MEV protection
- The same `slippageTol` parameter is applied to two distinct swaps with different token denominations, making the check incorrect for at least one
- Spot prices from AMM reserves (`getReserves()`) are used for fee or collateral valuation without TWAP protection
- Bridge liquidity operations omit minimum amount parameters

**Detection Heuristics**
1. Find all DEX router calls and check whether `amountOutMin` is 0 or hardcoded to a constant
2. Identify `block.timestamp` used as the `deadline` parameter in any swap call
3. Check bridge functions that execute swaps on the destination side for user-configurable slippage
4. Look for `getReserves()` or `balanceOf`-derived pricing in fee or collateral valuation logic
5. Verify every swap parameter that can be sandwiched is either user-specified or derived from a manipulation-resistant oracle

**False Positives**
- Atomic arbitrage within a single transaction where price is guaranteed by construction
- Admin-controlled rebalancing routed via private mempool with off-chain slippage enforcement
- Functions where a separate oracle-derived check independently enforces minimum output

**Notable Historical Findings**
Connext audits documented that users were forced to accept any slippage on the destination chain because `xcall` offered no mechanism for the initiating user to specify a destination-side minimum output, and separately that `SponsorVault` used an AMM spot price for fee calculation, making it directly exploitable via sandwich attack. WooFi's cross-chain router was found not to correctly enforce slippage in `crossSwap`, allowing large cross-chain swaps to receive heavily discounted outputs. The Juicebox protocol audit found that a delegate architecture forced callers to set zero slippage with no override mechanism.

**Remediation Notes**
Bridge interfaces must accept a user-specified `minAmountOut` and `deadline` for any swap executed on the destination side, even when the swap is performed by a relayer on the user's behalf. Any pricing derived from on-chain AMM state must be validated against a Chainlink or TWAP oracle with an acceptable deviation bound before being used in bridge fee or collateral calculations.

---

### Denial of Service and Gas Griefing (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Withdrawal queues are activated globally when any single transfer exceeds the flow rate limit, allowing an attacker to delay all bridge withdrawals at minimal cost
- Cross-chain message handlers (`lzReceive`, Connext `execute`) can be fed malicious calldata that causes an unrecoverable revert, permanently blocking the message channel
- Unbounded loops over pending withdrawals or inbound message roots exceed the block gas limit as arrays grow
- Gnosis Safe threshold updates can be triggered to exceed the count of valid signers, bricking the multisig guard

**Detection Heuristics**
1. Identify all flow rate or withdrawal queue mechanisms; check whether activation is global or per-token and per-user
2. Examine cross-chain message handler callbacks for unbounded gas cost or revert paths with no recovery mechanism
3. Find loops over dynamic arrays that grow with protocol usage; confirm they are paginated or bounded by a constant
4. Calculate the cost for an attacker to activate the rate limit versus the damage inflicted on legitimate users

**False Positives**
- Global rate limiting serving as an intentional circuit breaker with a documented governance override path
- Loops bounded by a small configuration constant that cannot be inflated by user action
- Message handlers that use try/catch to isolate per-message failures without blocking the channel

**Notable Historical Findings**
Immutable's bridge had a flow rate check that activated a global withdrawal queue, meaning a single attacker transaction slightly above the threshold would delay every pending withdrawal across all users and tokens. Axelar ITS had two separate high-severity DoS findings: one where the bridge could be blocked by initializing an ITSHub balance for a wrong chain, and another where bridging to a chain with no deployed interchain token caused a permanent DoS on that route. Holograph found a critical issue where an operator could set a destination gas limit above the destination chain's block gas limit, permanently preventing message execution.

**Remediation Notes**
Flow rate limits must be tracked and enforced per-token; activation of a queue for one token must not affect withdrawals of other tokens. Cross-chain message handlers must use try/catch with a stored-payload retry mechanism so that a failed individual message does not block the entire channel. Withdrawal loops must be paginated with an explicit batch size parameter enforced at the call site.

---

### Oracle and Price Feed Issues (ref: fv-sol-10, fv-sol-10-c5, fv-sol-10-c6, fv-sol-10-c7)

**Protocol-Specific Preconditions**
- Chainlink `latestRoundData()` is called without checking `updatedAt` staleness, `answeredInRound >= roundId`, or `price > 0`
- Unhandled Chainlink reverts (e.g., access-controlled feeds on some L2s) cause a total DoS of all price-dependent operations
- TWAP oracles register token pairs in the wrong order, returning the inverse price
- Balancer read-only reentrancy allows a bridge pricing function to read pool balances during a mid-transaction vault callback

**Detection Heuristics**
1. Find every `latestRoundData()` call; verify staleness, round completeness, and positivity checks are all present
2. Wrap Chainlink calls in `try/catch` and confirm a fallback oracle or cached price is used on revert
3. For TWAP implementations, verify token0/token1 order matches the actual pool ordering
4. Identify any view function reading Balancer pool balances; check whether it is callable during a Balancer vault callback from the same transaction

**False Positives**
- Oracle used only for non-critical off-chain display output
- Protocol with a correctly implemented and tested secondary oracle fallback

**Notable Historical Findings**
Juicebox audits found that Chainlink oracle data could be outdated and used without staleness validation, and separately that an unhandled Chainlink revert would lock all price oracle access. Vader Protocol had two findings where the TWAP oracle registered tokens in the wrong order and where the TWAP average itself was computed incorrectly, both producing systematically wrong prices throughout the protocol. WooFi's oracle failed silently when the Chainlink price fell outside acceptable bounds, with no fallback mechanism to prevent the bridge from operating on stale prices.

**Remediation Notes**
All Chainlink calls in bridge contracts must use the full validation pattern: positive price, non-zero `updatedAt`, `answeredInRound >= roundId`, and a configurable `MAX_STALENESS` constant. The call must be wrapped in `try/catch` with a documented fallback. Staleness thresholds must be set conservatively relative to the feed's published heartbeat and tightened for feeds on chains with unreliable sequencers.

---

### Cross-Chain Message Verification and Replay (ref: fv-sol-4-c10, fv-sol-4-c11)

**Protocol-Specific Preconditions**
- Cross-chain message handlers do not verify that `msg.sender` is the trusted bridge endpoint, or do not verify the original sender address on the source chain
- Signed payloads omit `block.chainid` or the contract address, making them valid on every chain where the contract is deployed
- Processed message IDs or nonces are not tracked, allowing the same proof or signature to be submitted multiple times
- Gas limits for cross-chain execution are hardcoded or underestimated; messages that exceed the limit fail permanently with no retry path
- Diamond proxy facet upgrades do not track which cuts have been applied, allowing replay of already-executed upgrades

**Detection Heuristics**
1. Verify every cross-chain message handler checks `msg.sender == trustedBridgeEndpoint` and validates the original source chain sender
2. Confirm that processed message IDs are written to storage before execution to prevent replay within the same transaction
3. Check that signed payloads include `block.chainid`, `address(this)`, and a nonce or unique message ID
4. Verify that cross-chain gas limits are configurable and that a minimum floor is enforced at call time
5. Check `diamondCut` implementations for per-cut deduplication tracking

**False Positives**
- Bridge transport layers (LayerZero, Wormhole) that natively enforce sender verification and message deduplication at the protocol level, provided the application layer correctly validates the transport-layer guarantees
- Idempotent operations where duplicate delivery has no additional state impact

**Notable Historical Findings**
Connext audits found that router signatures could be replayed on the destination domain because the signed hash omitted the destination chain ID, and that `diamondCut` allowed already-applied facet updates to be re-executed, potentially reverting security fixes. Biconomy had a cross-chain signature replay vulnerability where a valid signature issued on one chain could be submitted on any other chain where the same contract was deployed. In the Era (zkSync) audit, priority operations could be re-executed when migrating from Gateway to L1 because neither system had recorded the operation as already processed.

**Remediation Notes**
Every cross-chain message handler must follow a strict sequence: (1) verify `msg.sender` is the bridge endpoint, (2) verify the source chain identifier and sender address, (3) mark the message as processed in storage, (4) execute. Steps one through three must be atomic and must precede any state changes or external calls. Gas limits must be parameterized per message with a protocol-enforced minimum covering the worst-case destination execution cost, and a retry or refund mechanism must exist for messages that fail due to insufficient gas.

---

### External Call Injection (ref: fv-sol-4-c6)

**Protocol-Specific Preconditions**
- Bridge executor or router contracts forward arbitrary calldata supplied by users to arbitrary target addresses with no whitelist restriction
- Token approvals are granted to user-supplied addresses before the external call executes
- `delegatecall` is used with a target derived from user input, running untrusted code in the contract's own storage context
- Executor contracts hold residual token balances between transactions, making them profitable to drain via crafted calldata

**Detection Heuristics**
1. Find all `.call()` and `.delegatecall()` invocations; check whether the target address originates from user input or a trusted whitelist
2. Verify function selector validation: the first 4 bytes of calldata should be compared against an allowed-selector mapping before forwarding
3. Audit token approvals granted before external calls; confirm the approval target is an immutable or whitelisted address
4. Check whether executor or router contracts accumulate token balances; if so, confirm no external call path can redirect those balances

**False Positives**
- Calls to hardcoded, immutable contract addresses where the target cannot be influenced by callers
- Functions restricted to admin or trusted operator roles with no user-controlled parameters

**Notable Historical Findings**
LI.FI's `GenericBridgeFacet` accepted arbitrary bridge addresses and calldata, allowing an attacker to pass a malicious target that drained approved tokens in a single transaction. Connext's `Executor` held unclaimed tokens between bridge steps and was exploitable via crafted calldata that redirected those tokens to an attacker-controlled address before the intended recipient claimed them. Biconomy's paymaster contract allowed theft by constructing a specific relayed transaction that triggered an arbitrary external call using the contract's own existing token approvals.

**Remediation Notes**
Bridge executor contracts must maintain an explicit allowlist of callable target addresses and permissible function selectors. Token approvals must be granted only to whitelisted addresses, consumed atomically in the same transaction, and revoked immediately after use. Executor contracts must not hold persistent token balances; residual tokens after each execution should be swept to a designated recovery address.

---

### Flow Rate and Rate Limiting (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Bridge flow rate limits apply globally across all users when any single user exceeds the per-token threshold, enabling griefing at minimal cost
- Alternative entry points (e.g., deploying a second `TokenManager` instance) bypass the primary rate limit check
- Per-transfer size caps are absent, allowing a single large transfer to exhaust the bridge's available liquidity within one transaction
- Rate limit thresholds are set in nominal token amounts and are not adjusted as token prices change, making fixed thresholds economically meaningless over time

**Detection Heuristics**
1. Check whether rate limit activation triggers a global withdrawal queue or a per-token queue
2. Identify all code paths that result in a token transfer; confirm each path is subject to the same rate limit check
3. Calculate the cost for an attacker to activate the rate limit relative to the damage inflicted on legitimate users
4. Check whether large individual transfers can bypass per-period rate limits through a single transaction

**False Positives**
- Intentional global circuit breakers activated only by governance with a documented and timelocked override path
- Rate limits where the activation threshold requires economic exposure exceeding the attacker's potential benefit

**Notable Historical Findings**
Immutable's bridge had a flow rate check that activated a global withdrawal queue on the first token that exceeded its threshold, meaning a single attacker transaction just above the limit would delay every pending withdrawal for all users across all tokens. Axelar ITS had a finding where the `TokenBalance` limit could be bypassed entirely by deploying a new `TokenManager` instance, as the limit was enforced at the manager level rather than at the bridge level. A separate Axelar finding demonstrated that ERC-777 token support in the `TokenManager` broke the flow limit logic because the re-entrant hook could trigger multiple limit evaluations within a single transfer.

**Remediation Notes**
Rate limit state must be tracked and enforced per-token; activation of a restricted mode for one token must not affect withdrawals of other tokens. Every code path that moves tokens out of the bridge must pass through the same rate limit check. Token manager deployments must be authenticated to prevent bypass via new instances. Consider expressing rate limits in USD value using a price oracle rather than in nominal token amounts to maintain consistent security properties over time.

---

### State Update Inconsistency (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Burn or cancel operations do not clear all associated mappings (e.g., `orderOwner` persists after NFT burn), enabling the next mint of the same token ID to inherit stale ownership
- Signer count or threshold counters are decremented unconditionally rather than only when the removed entity was actually active, causing the threshold to exceed the valid signer count
- Domain separator or name hash caches are not invalidated when the underlying value changes
- Array swap-and-pop removals update the array but not the associated index mapping, corrupting future lookups on the swapped element
- Cross-chain accounting fails to synchronize source-chain locked amounts with destination-chain minted amounts when intermediate steps fail or are retried

**Detection Heuristics**
1. For every remove, burn, or cancel operation, enumerate all state variables referencing the affected entity and verify each is cleared
2. Check counter variables (signer counts, total supply, cumulative balances) for correctness on both increment and decrement paths
3. Verify that cached computed values (domain separators, price accumulators) are invalidated when any of their inputs change
4. For swap-and-pop array patterns, confirm the index mapping for the moved element is updated before the pop executes

**False Positives**
- Deliberately lazy state updates reconciled by a keeper in a subsequent transaction, with the interim inconsistency documented and bounded
- State variables used only for historical reference or off-chain indexing with no on-chain security impact

**Notable Historical Findings**
CLOBER audits found that `orderOwner` was not zeroed after an NFT burn, allowing the next mint of the same token ID to inherit stale ownership and enabling order theft. Connext audits identified that the domain separator was not rebuilt after a `name` change, causing EIP-712 signatures to silently fail for users whose clients had cached the new name. Hats Protocol had a finding where `_removeSigner` decremented `signerCount` even when the removed signer was already invalid, causing the threshold to be set higher than the actual number of valid signers and bricking the Safe module.

**Remediation Notes**
Any operation that removes an entity from the bridge (token manager deregistration, signer removal, route deletion) must include an explicit cleanup pass over all mappings that reference that entity. Threshold and counter arithmetic must guard against double-decrement by checking whether the entity is active before modifying the counter. Domain separators must be rebuilt atomically within any setter that modifies the values they encode.

---

### ERC4626 Vault Integration Issues (ref: fv-sol-2-c6)

**Protocol-Specific Preconditions**
- Bridge-connected vaults are vulnerable to first-depositor share price inflation when no virtual shares offset is present
- The `mint` function uses the `shares` parameter in the `transferFrom` call where it should use the computed `assets` value, under-collecting tokens
- `maxDeposit`, `maxWithdraw`, and `maxRedeem` do not return 0 when the vault is paused or at capacity, causing integrators to attempt operations that will revert
- Lossy yield strategies cause the vault exchange rate to fall below 1:1, under-collateralizing the bridge's outstanding liabilities
- Preview functions disagree with actual execution amounts due to fees or limits not reflected in the preview

**Detection Heuristics**
1. Check for virtual shares or an equivalent mechanism protecting against share price inflation on the first deposit
2. Compare `previewDeposit`/`previewRedeem` return values against actual `deposit`/`redeem` return values; any discrepancy indicates a specification violation
3. Verify that all `max*` functions return 0 when the contract is paused or capped
4. Check that `mint()` and `deposit()` use the correct parameter (`assets` vs. `shares`) in the token `transferFrom` call
5. Verify round-trip consistency: depositing then immediately redeeming must not lose funds beyond a 1-wei rounding tolerance

**False Positives**
- Vaults using OpenZeppelin's ERC4626 virtual shares offset, which is an accepted mitigation for inflation attacks
- Vaults that document and disclose non-compliance with specific EIP-4626 clauses

**Notable Historical Findings**
Tribe's `xERC4626` used the wrong `amount` parameter in the `mint` function, causing callers to receive shares without transferring the correct asset quantity. PoolTogether v5 audits produced numerous ERC4626 compliance findings, including a case where the vault's internal exchange rate could only decrease and never recover from a lossy strategy, permanently under-collateralizing outstanding shares over time. GoGoPool's `TokenggAVAX` returned incorrect values from `maxWithdraw` and `maxRedeem` when the contract was paused, causing external integrators to attempt operations that would immediately revert.

**Remediation Notes**
Bridges that custody assets in ERC4626 vaults must validate full specification compliance before integration, including paused-state behavior of all `max*` functions. First-deposit inflation attacks are mitigated by OpenZeppelin's virtual shares pattern; any custom vault implementation must replicate this protection. Exchange rate decreases due to lossy strategies must be handled explicitly, either by pausing withdrawals or by maintaining a separate solvency reserve proportional to outstanding bridge liabilities.

---

### Non-Standard Token Handling (ref: fv-sol-2-c7, fv-sol-6-c10)

**Protocol-Specific Preconditions**
- Bridge accepts fee-on-transfer tokens but records the nominal transfer amount rather than the actual balance delta, overstating the locked amount and permitting over-release on the destination chain
- USDT-style tokens require the approval amount to be set to 0 before setting a new non-zero value; omitting this causes a revert that blocks bridge operations
- ERC-777 tokens trigger `tokensReceived` callbacks that re-enter bridge logic before accounting is finalized
- Tokens with non-standard or mutable `decimals()` values are not normalized before cross-chain amount encoding
- Rebasing tokens (e.g., stETH, aTokens) change their balance between the lock event and the corresponding release, causing systematic accounting drift

**Detection Heuristics**
1. Confirm all `transferFrom` calls use a balance-before/balance-after delta to record the actual received amount rather than the input parameter
2. Search for `IERC20(token).approve(` calls that do not reset allowance to 0 before setting a new value
3. Identify tokens explicitly supported by the bridge; flag any with non-standard behavior (fee, rebase, ERC-777) and verify each has explicit handling
4. Check `decimals()` usage in all cross-chain amount scaling paths; verify it is called dynamically rather than hardcoded
5. Verify `safeTransfer` and `safeTransferFrom` are used throughout rather than bare `transfer` and `transferFrom`

**False Positives**
- Bridges that explicitly document and enforce a whitelist of non-fee-on-transfer, non-rebasing tokens
- Approval calls where the contract is known to consume the full allowance in the same transaction and the token is not USDT-like

**Notable Historical Findings**
Axelar ITS had balance tracking completely broken for rebasing tokens because the bridge locked a snapshot amount but the rebased balance changed before and after the cross-chain operation, enabling attackers to exploit the gap. A separate Axelar finding showed that ERC-777 reentrancy allowed `expressReceiveToken` to be re-entered before the express delivery was marked as settled, enabling double delivery. LI.FI received multiple findings for not resetting token allowances after swaps, leaving residual approvals that could be exploited by subsequent callers interacting with the same bridge contract.

**Remediation Notes**
Bridge contracts must use the balance-delta pattern for every inbound token transfer unconditionally, regardless of whether the token is expected to be fee-on-transfer. USDT compatibility requires the two-step approve pattern (set to 0, then set to amount). ERC-777 support requires re-entrancy guards on all token receipt paths. Rebasing tokens should either be explicitly unsupported and blocked, or converted to a non-rebasing wrapper before bridging.

---

### Native ETH Handling (ref: fv-sol-5-c8)

**Protocol-Specific Preconditions**
- `msg.value` sent to a bridge function is not forwarded to the downstream messaging layer, leaving ETH permanently stranded in the bridge contract
- Excess ETH above the required fee is not refunded to the caller
- Inconsistent ETH/WETH handling causes some code paths to wrap ETH while others pass it as native, resulting in mismatched accounting on the destination side
- Arbitrum retryable ticket creation uses an incorrect function variant, causing aliasing issues that prevent fund recovery
- Wormhole bridge facets omit the `{value: msg.value}` syntax on the bridge call, sending the message without the required attached value

**Detection Heuristics**
1. For every `payable` function, trace `msg.value` through all downstream calls and verify none is left unaccounted
2. Check whether excess ETH (`msg.value - requiredFee`) is explicitly refunded to `msg.sender` using a success-checked low-level call
3. Audit ETH-to-WETH wrapping paths for asymmetry: every `weth.deposit` should have a corresponding `weth.withdraw` on paths that need native ETH output
4. Verify L2-specific bridge calls (Optimism, Arbitrum, zkSync) use the correct function signatures for fee forwarding and refund aliasing

**False Positives**
- Contracts that intentionally collect excess ETH as a fee, with this behavior documented
- Atomic wrap/unwrap within a single transaction where no value can be stranded

**Notable Historical Findings**
LI.FI's Wormhole facet was found not to include the native token in the bridge call, and the Arbitrum facet used the wrong function to create retryable tickets, causing submitted fees to be unrecoverable. Connext's executor and asset logic handled native tokens inconsistently across code paths, causing `execute()` to revert when the bridge had forwarded native ETH instead of WETH. Decent's bridge sent any ETH refunded by the destination router to the `DecentBridgeAdapter` contract address rather than back to the original caller, permanently locking refunded value.

**Remediation Notes**
Every `payable` bridge function must forward `msg.value` in full to the underlying messaging layer using explicit `{value: msg.value}` syntax. Excess ETH must be returned to `msg.sender` via a low-level call with a checked success flag. ETH and WETH must be handled through a single canonical adapter function to eliminate mixed-handling inconsistencies. L2-specific fee mechanics (Arbitrum, Optimism, zkSync) must be tested with the exact function variants documented by the respective bridge infrastructure.

### lzCompose Sender Impersonation (ref: pashov-7)

**Protocol-Specific Preconditions**
- The bridge contract implements `lzCompose` but does not validate that `msg.sender` is the trusted LayerZero endpoint
- The `_from` parameter is accepted without checking it matches the expected OFT or OApp peer address
- Nested compose messages degrade the sender context to `address(this)`, allowing a malicious contract to impersonate the OFT when triggering a composed call
- The contract grants privileged actions (mints, unlocks, parameter changes) inside `lzCompose` based solely on the unvalidated `_from` argument

**Detection Heuristics**
1. Locate every `lzCompose` implementation; verify `require(msg.sender == address(endpoint))` is the first check
2. Verify `_from` is validated against a stored peer or trusted OFT address before executing any state-changing logic
3. Check whether the contract supports nested compose messages; if so, confirm the sender context is explicitly re-validated at each composition level
4. Search for any privilege escalation inside `lzCompose` (mint, unlock, transfer) that executes before both sender checks are satisfied

**False Positives**
- `lzCompose` implementations that use the standard `OAppReceiver` modifier, which already enforces both `msg.sender == endpoint` and peer validation
- Contracts where `lzCompose` performs only read-only or idempotent operations with no economic impact

**Notable Historical Findings**
Tapioca USDO/TOFT exploit: a HIGH severity finding where the `lzCompose` implementation omitted both the endpoint sender check and the `_from` peer check, allowing an attacker to call `lzCompose` directly and trigger unauthorized token operations by fabricating the `_from` parameter.

**Remediation Notes**
Every `lzCompose` implementation must begin with `require(msg.sender == address(endpoint))` followed by `require(_from == trustedPeer[srcEid])`. The standard `OAppReceiver` modifier enforces this pattern and should be used without modification. Protocols that support nested compose chains must treat each composition level as a fresh, unvalidated call and re-apply sender verification at every level.

---

### Delegate Privilege Escalation (ref: pashov-38)

**Protocol-Specific Preconditions**
- The OApp calls `endpoint.setDelegate(delegateAddress)` but the delegate address is an EOA, a hot wallet, or a contract with weaker access controls than the OApp owner
- `setDelegate` is protected by a lesser access control than `setPeer`, allowing an actor who cannot register peers to nonetheless reconfigure DVNs, executors, and message libraries
- The delegate has the ability to call `skipPayload` or `clearPayload`, effectively censoring or selectively dropping cross-chain messages
- No governance timelock separates the `setDelegate` transaction from the configuration change taking effect

**Detection Heuristics**
1. Find all calls to `endpoint.setDelegate`; verify the supplied address is identical to the OApp owner or is governed by at least the same multisig and timelock
2. Confirm `setDelegate` is guarded by the same access modifier as `setPeer` and other critical OApp configuration functions
3. Check whether the current delegate can unilaterally invoke `skipPayload`, `clearPayload`, or library version overrides without additional authorization
4. Audit deployment and initialization scripts to confirm no EOA retains the delegate role after the protocol goes live

**False Positives**
- Delegate set to the same multisig address as the OApp owner, making the privilege equivalent
- Protocols where the delegate is a governance timelock contract, providing a delay window for community response

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
The delegate role must be treated as equivalent in power to the OApp owner. The safest pattern is `setDelegate(address(this))` or `setDelegate(owner())`, ensuring no external party can reconfigure the security stack. Where a distinct delegate is operationally necessary, it must be a multisig with a timelock, and its authority should be narrowly scoped to non-security-critical operations if the LayerZero SDK allows such restriction.

---

### Cross-Chain Supply Accounting Invariant Violation (ref: pashov-39)

**Protocol-Specific Preconditions**
- The bridge's fundamental invariant `total_locked_source >= total_minted_destination` is not enforced by on-chain code or continuously monitored off-chain
- Decimal conversion between chains is implemented incorrectly, causing the destination to mint more tokens than were locked on the source
- `_credit` is callable through a path that does not require a corresponding `_debit` to have been executed, allowing minting without locking
- Race conditions exist in multi-chain deployments where two destinations can both process the same source event due to a missing uniqueness check
- Any off-path function (emergency recovery, admin mint, airdrop) can increase the destination supply without modifying the source lock accounting

**Detection Heuristics**
1. Map every code path that calls `_credit` or any equivalent minting function; verify each path is exclusively reachable via `lzReceive` from a verified peer
2. Confirm decimal conversion is tested for all token/chain combinations; verify that `sharedDecimals` normalization correctly handles non-18-decimal tokens
3. Check for emergency or admin functions that can mint on destination or unlock on source without updating the complementary accounting on the other chain
4. Verify replay protection ensures each source-chain event triggers at most one destination credit
5. Review multi-chain topologies (hub-and-spoke vs. mesh) for scenarios where a message can be delivered to two destinations from a single debit

**False Positives**
- Protocols that implement conservative rate limits capping maximum per-window minting, limiting exposure even if the invariant is temporarily violated
- Bridges where `_credit` is callable only via a verified `lzReceive` path and the LayerZero endpoint enforces message uniqueness

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
The invariant `total_locked_source >= total_minted_destination` must be maintained across every code path. `_credit` must be callable exclusively through `lzReceive` from a verified peer address; no admin or emergency shortcut should bypass this path. Decimal conversion must be unit-tested for every supported token and chain pair. Rate limits on cross-chain transfers provide a defense-in-depth layer that caps maximum exposure if the invariant is momentarily violated by an undiscovered bug.

---

### Ordered Message Channel Blocking (ref: pashov-42)

**Protocol-Specific Preconditions**
- The OApp uses ordered nonce execution, meaning messages from a given source must be processed in strict sequence on the destination
- At least one message type can permanently revert on the destination due to invalid state, a reverted recipient contract call, or an out-of-bounds operation
- No administrative mechanism (skipPayload, clearPayload, admin override) is available or access-controlled to an entity that can respond quickly to a channel freeze
- An attacker can craft a message whose payload is guaranteed to revert on the destination, requiring only the one-time cross-chain messaging fee to freeze the entire channel indefinitely

**Detection Heuristics**
1. Determine whether the OApp uses ordered or unordered nonce mode; ordered mode is the risk-bearing configuration
2. Identify every revert condition inside `_lzReceive`; for each one, assess whether an attacker can deliberately trigger it via crafted message content
3. Verify whether `_lzReceive` is wrapped in a try/catch that records and skips permanently-failing messages rather than propagating the revert
4. Confirm that `skipPayload` or `clearPayload` exists and is callable by an actor who can respond within the expected channel-freeze impact window
5. Check whether the `NonblockingLzApp` pattern (V1) or its V2 equivalent is used to decouple message failures from channel progression

**False Positives**
- OApps using LayerZero V2 unordered nonce mode, where a single failed message does not block subsequent messages from the same source
- `_lzReceive` implementations so simple (single mapping write) that a revert is geometrically impossible given valid message encoding

**Notable Historical Findings**
Code4rena Maia DAO finding #883: an ordered nonce OApp was found to be permanently blockable because a single crafted message could permanently revert on the destination, freezing all subsequent messages from that source chain indefinitely with no recovery path.

**Remediation Notes**
Bridge and OFT contracts should default to LayerZero V2 unordered nonce mode unless message ordering is a strict protocol requirement. Where ordering is required, `_lzReceive` must be wrapped in a try/catch that stores failing messages for later manual retry rather than propagating the revert. An accessible `skipPayload` or `clearPayload` function guarded by a sufficiently responsive multisig must be available as a last-resort recovery mechanism.

---

### State-Time Lag Exploitation via lzRead (ref: pashov-44)

**Protocol-Specific Preconditions**
- The protocol uses `lzRead` to query state on a remote chain and then acts on the result delivered by `lzReceive`, with a non-trivial and non-deterministic latency between query submission and result delivery
- Decisions made from the read result are irreversible (token mints, collateral unlocks, position closures) and carry economic value proportional to the queried state
- The queried state (token ownership, position health, balance) can change between the moment of query and the moment the result is acted upon
- No on-chain re-validation of the read result occurs before the irreversible action is executed

**Detection Heuristics**
1. Identify every `lzRead` invocation; for each one, determine what state is queried and whether that state can change between query and delivery
2. Assess whether the action triggered by the `lzReceive` callback is reversible or irreversible; irreversible actions on stale read results are the primary risk
3. Check whether the destination contract re-validates the read result against current on-chain state before executing the privileged action
4. Evaluate the latency window: longer windows increase the probability and severity of state changes between query and execution

**False Positives**
- `lzRead` used exclusively to query immutable or append-only data (contract deployment bytecode, historical block hashes) that cannot change between query and delivery
- Protocols that treat the read result as a hint and perform a fresh on-chain state check before executing any irreversible action

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Irreversible cross-chain actions must not be based solely on `lzRead` results. The safe pattern requires the destination contract to re-validate the critical condition (e.g., re-checking `ownerOf(tokenId)` or balance on the local chain, or requiring a fresh signed attestation) at the time of execution rather than trusting the cross-chain read result. `lzRead` is appropriate for slowly-changing or immutable data; time-sensitive authorization decisions require fresh on-chain state.

---

### OFT Shared Decimals Truncation (ref: pashov-47)

**Protocol-Specific Preconditions**
- The OFT token uses a non-standard `sharedDecimals` configuration where `sharedDecimals >= localDecimals`, eliminating the intended precision reduction and making `_toSD()` a no-op conversion that still casts to `uint64`
- Transfer amounts can exceed `type(uint64).max` (~18.4e18) in absolute units, causing silent truncation in the `uint64` cast inside `_toSD()` with no revert
- A custom fee mechanism is applied before `_removeDust()` is called, causing the fee to be calculated on a pre-dust-removal amount that differs from the actual transferred amount
- The OFT is deployed with `localDecimals == 18` and `sharedDecimals == 18`, which is a non-standard configuration that bypasses the decimal normalization designed to prevent `uint64` overflow

**Detection Heuristics**
1. Read the OFT constructor to determine `localDecimals` and `sharedDecimals`; flag any configuration where `sharedDecimals >= localDecimals`
2. Identify the maximum transferable amount in absolute token units; verify it does not exceed `type(uint64).max` after division by `10 ** (localDecimals - sharedDecimals)`
3. Locate custom fee or deduction logic; verify it is applied after `_removeDust()` is called, not before
4. Check whether transfer amounts are validated against `uint64.max` before the `_toSD()` conversion

**False Positives**
- Standard OFT deployments using the default `sharedDecimals = 6` with `localDecimals = 18`, where the `_toSD()` conversion reduces amounts by `10^12` before the `uint64` cast, making overflow practically impossible for realistic token supplies
- Protocols where fee logic is explicitly applied after dust removal and tested with amounts near the `uint64` boundary

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
OFT contracts must use `sharedDecimals = 6` (the LayerZero default) with `localDecimals = 18`. Custom fee logic must be applied after `_removeDust()` to ensure fees are calculated on the same amount that will be transferred. Transfer amounts should be validated with `require(amountLD <= type(uint64).max * decimalConversionRate)` before invoking `_toSD()` to surface overflow conditions as explicit reverts rather than silent truncation.

---

### Cross-Chain Address Ownership Variance (ref: pashov-59)

**Protocol-Specific Preconditions**
- The bridge or OApp uses `lzRead` to check `ownerOf(tokenId)` or `balanceOf(address)` on a remote chain and grants rights to the same address on the local chain, assuming address identity implies ownership identity across chains
- One or more supported chains use `CREATE`-based deployment where the same address can be controlled by entirely different parties depending on nonce history on each chain
- An EOA key used on one chain has never been imported or used on another chain, meaning the address exists in a different security context
- Authorization is granted based on address equality across chains rather than through a verified cross-chain message from an authorized peer

**Detection Heuristics**
1. Search for any cross-chain read (`lzRead`, oracle query, off-chain attestation) that resolves to an address, then grants rights to that same address on the local chain
2. Identify whether the cross-chain authorization path uses address equality (`localAddress == remoteAddress`) rather than an explicit (chainId, address) pair mapping
3. Check peer mappings: verify they bind (srcChainId, srcAddress) as a composite key, not srcAddress alone
4. Audit `CREATE`-deployed contracts that appear at the same address on multiple chains; verify the deployer and constructor arguments are identical, confirming the same entity controls both

**False Positives**
- `CREATE2`-deployed contracts where the factory address, salt, and init code hash are all identical across chains, which cryptographically guarantees the same controlling entity
- Protocols that use cross-chain messaging (not address equality) to prove ownership: e.g., a message signed by the remote owner and verified by a registered peer

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Cross-chain authorization must never rely on address equality as a proxy for ownership identity. The safe pattern binds authorization to an explicit `(chainId, address)` pair stored in a peer registry. Ownership proofs for cross-chain operations must flow through verified cross-chain messages rather than address inference. `CREATE2` deployments with a deterministic factory provide a safe exception when the factory address, salt, and bytecode are verifiably identical across all target chains.

---

### Missing enforcedOptions - Insufficient Gas for lzReceive (ref: pashov-71)

**Protocol-Specific Preconditions**
- The OApp never calls `setEnforcedOptions()` to establish a minimum gas floor for destination execution, leaving gas entirely at the discretion of the message sender
- `lzReceive` on the destination performs non-trivial computation (multiple storage writes, external calls, token mints) that requires more gas than a user might supply with a minimal options configuration
- When `lzReceive` reverts on the destination due to out-of-gas, the source-chain debit has already been committed, leaving funds stranded in the LayerZero channel
- Recovery requires an admin to invoke `skipPayload` or the LayerZero executor to retry with adequate gas, both of which introduce delay and operational complexity

**Detection Heuristics**
1. Check whether `setEnforcedOptions` is called during deployment or initialization for each message type the OApp sends; a missing call is a finding
2. Measure the gas consumption of `_lzReceive` under worst-case conditions (maximum payload size, maximum number of storage writes); compare against the enforced minimum
3. Identify whether users can supply a custom `_options` bytes parameter that overrides gas limits; if so, verify `enforcedOptions` provides an absolute floor that cannot be undercut
4. Review the recovery path for stuck messages: confirm `skipPayload` or an equivalent mechanism is available and access-controlled appropriately

**False Positives**
- OApps where `_lzReceive` performs a single mapping write and the LayerZero executor's default gas grant is demonstrably sufficient under all conditions
- Protocols using an executor configuration that guarantees a minimum gas delivery regardless of user-supplied options

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Every OApp that sends cross-chain messages must call `setEnforcedOptions()` during initialization with gas limits derived from benchmarked worst-case `_lzReceive` execution costs, including a safety margin of at least 20%. Enforced options must be applied per message type. The LayerZero SDK's `Options.newOptions().addExecutorLzReceiveOption(gasLimit, value)` builder should be used to construct enforced options, and changes to enforced options after deployment must be governed by the same access controls as peer configuration.

---

### Insufficient Block Confirmations / Reorg Double-Spend (ref: pashov-114)

**Protocol-Specific Preconditions**
- The DVN relays cross-chain messages after a confirmation count that is below the chain's practical reorg depth, accepting messages as final before they are irreversibly settled
- The source chain has a history of reorgs at the configured confirmation depth (e.g., Polygon frequently reorgs at depths below 128 blocks, some L2 sequencers are centralized with known failure modes)
- An attacker can profitably execute a deposit on the source chain, receive bridged assets on the destination, and then cause or exploit a reorg to reverse the source deposit while retaining the destination assets
- The DVN does not differentiate between chains with probabilistic finality and chains with deterministic finality, applying the same low confirmation threshold universally

**Detection Heuristics**
1. Read the DVN configuration for each supported source chain; compare the `requiredConfirmations` value against publicly documented reorg depths and finality guarantees for that chain
2. For Polygon PoS, verify confirmations are at least 128; for Ethereum pre-merge, verify at least 12; for chains with probabilistic finality, require confirmation depths aligned with the economic value secured
3. Check whether the DVN configuration distinguishes between chains with fast cryptographic finality (e.g., post-merge Ethereum, most L1s with BFT consensus) and chains without it
4. Assess the economic profitability of a reorg attack given the bridge's liquidity depth and the cost of the required confirmations

**False Positives**
- Source chains with deterministic, near-instant finality (e.g., most modern BFT chains, Ethereum after finalization checkpoints) where reorgs beyond one or two blocks are cryptographically impossible
- DVN configurations that wait for finalized block tags rather than counting confirmations, providing stronger guarantees than confirmation counting

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Confirmation counts must be set chain-specifically based on each chain's finality guarantees, not as a uniform default. DVNs should wait for finalized block tags where the chain's RPC supports them (e.g., Ethereum's `finalized` tag). For chains with probabilistic finality, the confirmation depth should be calibrated against both the historical maximum reorg depth and the maximum economic value exposed per message. Rate limits on bridge transfers provide a complementary control by capping the value at risk in any single reorg window.

---

### Cross-Chain Message Spoofing (ref: pashov-117)

**Protocol-Specific Preconditions**
- The receiver contract's `lzReceive` or equivalent entry point does not verify that `msg.sender` is the trusted LayerZero endpoint address
- The `_origin.sender` field is not validated against a registered peer address for the originating chain ID, allowing fabricated origin data to pass unchecked
- The contract grants high-value actions (token mints, asset unlocks, privileged state changes) based solely on message content without validating the message delivery path
- A direct external call to the receive function with attacker-controlled parameters is indistinguishable from a legitimate endpoint delivery in the absence of sender verification

**Detection Heuristics**
1. Locate the `lzReceive` function or equivalent; verify the first two checks are `require(msg.sender == address(endpoint))` and `require(_origin.sender == peers[_origin.srcEid])`
2. Search for any function that processes cross-chain message content (minting, unlocking, state changes) without being exclusively reachable via the verified endpoint path
3. Verify the `onlyPeer` modifier or `_acceptNonce` function from the standard `OAppReceiver` is used and not overridden in a way that weakens either check
4. Test whether the receive function can be called directly from an external address without triggering an access control revert

**False Positives**
- Contracts that use the standard `OAppReceiver` base without modification, which already enforces both endpoint and peer validation
- Receive functions that are `internal` and exclusively called by a validated dispatcher that performs the endpoint and peer checks

**Notable Historical Findings**
CrossCurve bridge exploit (January 2026): an attacker called `expressExecute` directly with spoofed message data, bypassing the endpoint sender check entirely. The missing `msg.sender == endpoint` validation allowed the attacker to fabricate a cross-chain message and trigger unauthorized token minting, resulting in approximately $3M in losses.

**Remediation Notes**
Every cross-chain receive function must enforce both `msg.sender == address(endpoint)` and `_origin.sender == registeredPeer[_origin.srcEid]` as non-bypassable preconditions. The standard `OAppReceiver._lzReceive` wrapper provides these checks; custom receivers must replicate both. The endpoint address must be set at construction time as an immutable and must not be configurable post-deployment without governance controls.

---

### Unauthorized Peer Initialization (ref: pashov-119)

**Protocol-Specific Preconditions**
- `setPeer()` or `setTrustedRemote()` is callable by an account that does not require multisig authorization or a governance timelock
- The owner key used to call `setPeer` is an EOA without hardware wallet or multisig protection, making it susceptible to compromise
- The OApp's `allowInitializePath()` implementation accepts peers that have not been explicitly registered, falling back to permissive behavior
- No peer registry or deployment verification system is used to cross-check peer addresses against a canonical deployment manifest before registration

**Detection Heuristics**
1. Identify the access control on `setPeer` or `setTrustedRemote`; verify it requires a multisig with a meaningful threshold, not a single EOA
2. Check whether a timelock separates the `setPeer` transaction from the peer taking effect, providing a window to detect and respond to unauthorized changes
3. Review `allowInitializePath()`: verify it returns false for any (srcEid, sender) pair not explicitly registered via `setPeer`
4. Audit the deployment process to confirm peer addresses are verified against a canonical registry before being registered on-chain

**False Positives**
- Protocols where `setPeer` is governed by a multisig with timelock and peer addresses are verified against a published deployment registry before registration
- OApps using a factory pattern where peer addresses are deterministically computed and verified at deployment time

**Notable Historical Findings**
GAIN token exploit (September 2025): an attacker registered a fraudulent peer contract on the source chain by exploiting inadequate access control on the peer registration function. The fake peer was then used to trigger unauthorized minting of 5 billion tokens on the destination chain, with approximately $3M extracted before the protocol could respond.

**Remediation Notes**
`setPeer` must be protected by a multisig requiring at least two independent signers, combined with a timelock of at least 24 hours. `allowInitializePath()` must explicitly check `peers[_origin.srcEid] != bytes32(0)` and return false for unregistered origins. Peer addresses should be registered only after cross-referencing with a published deployment manifest. Post-registration, peer addresses should be treated as immutable unless a governance process with timelock and public notice is used to update them.

---

### Missing chainId / Message Uniqueness in Bridge (ref: pashov-140)

**Protocol-Specific Preconditions**
- The bridge does not maintain a `processedMessages` mapping or equivalent deduplication structure, allowing the same message to be processed more than once
- The message hash used for deduplication does not include the destination chain ID, enabling the same message to be replayed on a different chain that shares the same contract address
- The source chain ID is absent from the message hash, allowing messages originating from different chains to collide and be treated as equivalent
- No per-sender nonce is enforced, meaning message ordering and uniqueness depend solely on the content of the message rather than a monotonically incrementing counter

**Detection Heuristics**
1. Locate the message processing function; verify a `processedMessages[messageHash] = true` check and set operation surrounds the state-changing logic
2. Examine the message hash construction; confirm it includes `sourceChainId`, `destinationChainId`, a per-sender nonce, and the full payload
3. Check whether `require(block.chainid == destinationChainId)` is validated inside the receive function to prevent delivery to the wrong chain
4. Verify the contract address is included in the hash or that the hash is validated against a domain separator that encodes the contract address

**False Positives**
- Bridges that delegate replay protection to the underlying messaging layer (e.g., LayerZero endpoint enforces per-channel nonce uniqueness) and document this reliance explicitly
- Message types where replaying is economically harmless by design (e.g., price update messages that are idempotent)

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Every bridge must maintain a `processedMessages[keccak256(abi.encode(sourceChainId, destChainId, nonce, sender, payload))]` mapping and revert on any duplicate. The domain separator must encode both chain IDs and the contract address. A per-sender monotonic nonce must be included in the hash and incremented atomically on each processed message. Where the underlying messaging layer provides these guarantees, the bridge must document its reliance and verify the guarantees hold for every supported chain.

---

### DVN Collusion or Insufficient DVN Diversity (ref: pashov-142)

**Protocol-Specific Preconditions**
- The OApp is configured with a `1/1/1` security stack using a single required DVN and no optional DVNs, meaning one entity's compromise is sufficient to approve fraudulent messages
- Multiple DVNs are configured but are operationally or legally controlled by the same entity, or use the same underlying verification method (e.g., multiple DVNs all relying on the same oracle feed), eliminating meaningful independence
- The DVN configuration was set at deployment with no governance path for updating it as the DVN landscape evolves or as individual DVNs become compromised
- The OApp relies exclusively on the LayerZero default DVN configuration without explicitly overriding it, accepting whatever default the endpoint administrator has configured

**Detection Heuristics**
1. Read the OApp's `setConfig` call or configuration storage; identify `requiredDVNCount` and the list of required and optional DVN addresses
2. Research each configured DVN to determine its controlling entity and verification methodology; flag any two DVNs with shared control or shared underlying data sources
3. Verify the OApp does not fall back to the endpoint's default DVN configuration; an explicit override should be present
4. Check whether DVN configuration can be updated via governance with a timelock, or whether it is immutable post-deployment

**False Positives**
- OApps using a diverse DVN set with at least two independent entities applying different verification methods (light client, oracle-based, ZKP-based) and a threshold requiring at least two of them to agree
- Protocols that run their own required DVN in addition to third-party DVNs, reducing the ability of any single external party to approve fraudulent messages

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
OApps securing material value must configure at least a `2/3` DVN threshold using DVNs from independent entities that employ different verification methodologies. Using Google Cloud DVN, a ZKP-based DVN, and the protocol's own DVN provides diversity across both organizational and technical dimensions. The OApp should explicitly set its DVN configuration via `setConfig` rather than relying on endpoint defaults, and DVN configuration changes should require a governance timelock to prevent rapid reconfiguration by a compromised admin key.

---

### Missing Cross-Chain Rate Limits / Circuit Breakers (ref: pashov-143)

**Protocol-Specific Preconditions**
- The bridge or OFT contract enforces no per-transaction maximum transfer size, allowing a single transaction to transfer the entire locked asset pool if a vulnerability is exploited
- No time-window transfer cap (e.g., maximum N tokens per hour) limits the rate at which assets can flow through the bridge
- The contract has no `pause` function or the `pause` function is only callable by a single EOA key without a responsive on-call guardian arrangement
- Anomaly detection and automated pause triggers are absent, meaning an ongoing exploit continues unimpeded until manually detected

**Detection Heuristics**
1. Search for per-transaction `require(amount <= maxTransferSize)` checks on both send and receive paths; flag their absence
2. Check for time-window rate limiting: a moving-window accumulator pattern that reverts when the window's total exceeds a configured cap
3. Locate the `pause` function; verify it is callable by a multisig or guardian address that can respond within minutes, not only by a slow governance process
4. Assess the total value locked relative to the absence of rate limits; the risk severity scales with the amount that could be drained in a single transaction

**False Positives**
- Bridges where the total locked value is small enough that the gas cost of an exploit transaction constitutes a meaningful deterrent relative to the potential gain
- OFTs with per-chain supply caps enforced at the token contract level that effectively limit per-transaction exposure

**Notable Historical Findings**
Ronin bridge hack: the exploit drained approximately $625M over multiple transactions across six days before being detected. Per-window rate limits would have capped the loss to a fraction of this amount by triggering an automatic pause after the first anomalous window, providing time for human intervention.

**Remediation Notes**
All bridges securing material value must implement both per-transaction maximums and time-window rate limits on send and receive paths. The `whenNotPaused` modifier must be applied to all token movement functions. A guardian address - a multisig with on-call key holders - must have the ability to pause the bridge immediately without requiring a full governance vote. Automated monitoring that triggers a pause when transfer volume exceeds a statistical threshold should be deployed as an off-chain companion to the on-chain circuit breaker.

---

### Cross-Chain Reentrancy via Safe Transfer Callbacks (ref: pashov-156)

**Protocol-Specific Preconditions**
- The cross-chain receive function (`lzReceive`, `_credit`, or equivalent) calls `_safeMint` or `safeTransferFrom` before updating supply counters, ownership mappings, or bridge accounting state
- The recipient address is a contract that implements `onERC721Received` or `onERC1155Received` and uses the callback to initiate a new outbound cross-chain send on the same bridge
- The re-entrant outbound send executes before the original receive has updated the balance or supply state, creating a window where the asset appears to exist simultaneously on both chains
- The bridge lacks a reentrancy guard on the receive path, allowing the callback-triggered outbound send to fully execute before the original receive completes

**Detection Heuristics**
1. Locate every `_safeMint` and `safeTransferFrom` call inside cross-chain receive functions; verify all state updates (balances, supply counters, ownership records) precede the call
2. Check whether `nonReentrant` is applied to the receive path; its absence combined with a `_safeMint` call is a direct finding
3. Trace whether a re-entrant call into `send` or `_debit` from within `onERC721Received` / `onERC1155Received` would see consistent or stale bridge state
4. Consider replacing `_safeMint` with `_mint` on receive paths where the recipient is a user-specified address that could be a malicious contract

**False Positives**
- Receive functions that use `_mint` instead of `_safeMint`, which does not trigger any callback and therefore has no reentrancy surface
- Protocols where `nonReentrant` is applied to both the receive path and the send path, preventing the re-entrant outbound send from executing mid-receive

**Notable Historical Findings**
Ackee Blockchain cross-chain reentrancy proof-of-concept: a demonstration where `lzReceive` calling `_safeMint` before updating supply counters allowed a malicious `onERC721Received` callback to initiate a second bridge send, resulting in token duplication across chains.

**Remediation Notes**
The receive path must follow the Checks-Effects-Interactions pattern: all state updates (supply increments, ownership assignments, balance credits) must be committed before any safe transfer or mint callback. `nonReentrant` must be applied to the receive function. Where the callback is not required for contract recipient validation, `_mint` should be used instead of `_safeMint` to eliminate the callback surface entirely.

---

### Missing _debit Authorization in OFT (ref: pashov-159)

**Protocol-Specific Preconditions**
- The OFT contract overrides `_debit` or `_debitFrom` without including authorization logic verifying that the caller is permitted to burn or transfer tokens on behalf of `_from`
- The custom `_debit` implementation calls `_burn(_from, amount)` or `transferFrom(_from, address(this), amount)` without checking `msg.sender == _from` or verifying a sufficient allowance from `_from` to `msg.sender`
- The `send()` function does not enforce that `msg.sender == _from` before delegating to `_debit`, or it accepts `_from` as a caller-supplied parameter
- Any address can call `send()` specifying an arbitrary victim as `_from`, triggering an unauthorized burn or lock of that victim's tokens

**Detection Heuristics**
1. Locate any override of `_debit` or `_debitFrom`; verify it includes `require(msg.sender == _from || allowance[_from][msg.sender] >= amount)` before modifying token balances
2. Check `send()` to confirm `_from` is set to `msg.sender` internally and is not a caller-supplied parameter
3. If `send()` accepts `_from` as a parameter, verify the function contains `require(_from == msg.sender || isApprovedForAll(_from, msg.sender))` before invoking `_debit`
4. Compare the custom `_debit` implementation against the standard LayerZero OFT reference implementation; any divergence in authorization logic is a finding

**False Positives**
- Contracts using the standard LayerZero OFT implementation without any override of `_debit` or `_debitFrom`, which correctly derives `_from` from `msg.sender` inside `send()`
- Custom `_debit` implementations that include full ERC20 allowance validation and are covered by tests demonstrating rejection of unauthorized calls

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
Custom `_debit` implementations must replicate the authorization logic of the standard ERC20 `transferFrom` pattern: either `msg.sender == _from` or `allowance[_from][msg.sender] >= amount`, with the allowance decremented atomically on use. The safest approach is to avoid overriding `_debit` at all and instead extend the standard OFT's hook points. If an override is necessary, it must be reviewed against the standard implementation line-by-line to ensure no authorization step is omitted.

---

### Default Message Library Hijack (ref: pashov-160)

**Protocol-Specific Preconditions**
- The OApp does not explicitly pin its send library via `setSendLibrary()` or receive library via `setReceiveLibrary()` on the LayerZero endpoint, relying on the endpoint's mutable default library
- The LayerZero endpoint administrator updates the default message library to a new version, and the OApp silently adopts it without any notification, governance vote, or opportunity for the OApp to review the new library's security properties
- The new default library uses a different DVN or oracle validation mechanism than the one the OApp's security model was designed around, effectively changing the trust assumptions without the OApp's consent
- In a malicious or compromised scenario, a default library update could introduce a library that accepts fraudulent messages with reduced verification requirements

**Detection Heuristics**
1. Check whether the OApp calls `endpoint.setSendLibrary(oapp, eid, lib)` and `endpoint.setReceiveLibrary(oapp, eid, lib, 0)` during initialization; flag any missing explicit library pin
2. Verify the pinned library addresses are stored in a verifiable configuration and that changes require governance with a timelock
3. Review the LayerZero endpoint's default library history for the chains the OApp operates on; assess whether any past default update would have changed the OApp's security properties
4. Confirm the OApp has a governance-controlled mechanism to update its pinned library, as security updates to the library layer may be necessary over time

**False Positives**
- OApps that explicitly pin their library versions in the constructor or initialization function and have a governance-controlled update path with a timelock
- Protocols that have reviewed the LayerZero V2 EndpointV2's non-upgradeability guarantees and explicitly accept the mutable default library risk as documented

**Notable Historical Findings**
No specific historical incidents cited in source.

**Remediation Notes**
OApps must explicitly pin their send and receive library versions via `setSendLibrary` and `setReceiveLibrary` during deployment or initialization. Library pins should be treated as security-critical configuration and governed by the same multisig and timelock as peer addresses. A governance-controlled update path must exist so the OApp can adopt verified security patches to the library layer without emergency key ceremonies. The LayerZero V2 EndpointV2 is non-upgradeable, but library defaults remain mutable; explicit pinning is the only reliable mitigation.

---
