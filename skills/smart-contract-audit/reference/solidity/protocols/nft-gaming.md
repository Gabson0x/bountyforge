# NFT and Gaming Protocol Security Patterns

> Applies to: NFT marketplaces, NFT minting contracts, play-to-earn games, on-chain games, gamefi, NFT staking, trait-based NFTs, SeaDrop-style, OpenSea-style

## Protocol Context

NFT and gaming protocols combine token ownership semantics with game-state logic, creating a broader attack surface than pure DeFi. ERC-721 and ERC-1155 receiver callbacks (`onERC721Received`, `onERC1155Received`) make any external call during minting or transfer a potential reentrancy vector, and the fact that recipients can be contract wallets compounds this. Randomness is structurally adversarial in this domain: on-chain entropy is manipulable, VRF draw mechanics can be gamed by controlling subscription funding or redraw timing, and deterministic attribute generation in the same transaction as minting enables selective revert attacks. Royalty enforcement and metadata mutability (centralized URIs, mutable trait registries) represent trust assumptions that are frequently underspecified and often exploited.

---

## Bug Classes

### Reentrancy in Reward and NFT Claiming (ref: fv-sol-1)

**Protocol-Specific Preconditions**

The claiming function mints or transfers ERC-721/ERC-1155 tokens to `msg.sender` or an arbitrary address before finalizing state. The recipient is not guaranteed to be an EOA. Nonces, round counters, or claim flags are written after the external call. No `nonReentrant` guard is present on the function or its cross-entry equivalents.

**Detection Heuristics**

- Identify all functions invoking `_safeMint`, `safeTransferFrom`, or delegated minting helpers (e.g., `mintFromMergingPool`) and check whether state checkpoints precede the call.
- Trace nonce or claim-counter writes relative to token transfers in order-matching flows; a nonce set after the loop is a reliable indicator.
- Check whether a `nonReentrant` modifier is applied to all execution paths that ultimately call into the same state (separate entry points such as `takeOrders` can re-enter `matchOneToManyOrders`).

**False Positives**

- All relevant state (nonces, claim counters, balances) is finalized before any external call, satisfying Checks-Effects-Interactions.
- `_mint` is used instead of `_safeMint`, eliminating the callback.
- The recipient is verified to be an EOA at the call site.
- A `nonReentrant` modifier is applied consistently across all entry points touching shared state.

**Notable Historical Findings**

In the AI Arena audit, a `claimRewards` function iterated over unclaimed rounds and called an external `mintFromMergingPool` helper for each winning round before advancing `numRoundsClaimed`. A contract-wallet recipient could re-enter through `onERC721Received` and claim the same rounds repeatedly. The Infinity NFT Marketplace had a parallel pattern where an order nonce was written after all token and payment transfers in `matchOneToManyOrders`, allowing a re-entrant call to the same function to replay the settlement with the same nonce still unset.

**Remediation Notes**

Apply `nonReentrant` to all claim and order-execution functions, and move all state writes (nonces, round pointers, claim flags) above the first external call. Prefer `_mint` over `_safeMint` when the callback is not functionally required; this eliminates the reentry surface entirely without breaking token receipt for EOAs.

---

### Staking Rounding and Dust Amount Exploits (ref: fv-sol-2)

**Protocol-Specific Preconditions**

The protocol computes a staking factor or multiplier from the staked amount using integer division with a large denominator (e.g., `/ 10**18`) or a `sqrt` operation. A floor-to-one pattern rounds zero results up to one, granting disproportionate rewards for dust stakes. No minimum stake amount is enforced. Share-based staking pools may be vulnerable to first-depositor inflation if share calculation depends on current pool balance without dead-share protection.

**Detection Heuristics**

- Locate staking factor calculations using `sqrt` or large-denominator division on the staked amount; evaluate the minimum stake that avoids truncation to zero.
- Check for `if (factor == 0) { factor = 1; }` patterns that assign rewards to dust positions.
- Verify whether `curStakeAtRisk` or a loss penalty also truncates to zero for small stakes, creating asymmetric risk/reward.
- For vault/pool patterns, evaluate whether an attacker can donate tokens directly to the contract before the first deposit to inflate the share price to zero.

**False Positives**

- A minimum stake threshold is enforced at a level that prevents the divisor from reducing to zero.
- The staking factor is not used in reward distribution for zero-result inputs (protocol separately gates on minimum stake).
- Dead-shares pattern is used: initial shares minted to a burn address prevent inflation attack on first deposit.

**Notable Historical Findings**

In AI Arena, the staking factor was computed as `sqrt((amountStaked + stakeAtRisk) / 10**18)` with a floor of one. A user staking one wei obtained `stakingFactor = 1`, identical to a user with up to 3.99 tokens staked, yet `curStakeAtRisk` rounded to zero for such a tiny position, producing zero downside and positive upside. A separate inflation attack finding in the Stakepet protocol showed that a direct token donation to the contract before the first depositor allowed share issuance to round to zero, effectively stealing the deposit.

**Remediation Notes**

Enforce a minimum stake amount that guarantees the staking factor exceeds zero without artificial rounding. Remove floor-to-one behavior; revert or skip reward accounting for positions below threshold. For vault patterns, mint initial dead shares to a burn address in the constructor to make donation-based inflation economically infeasible.

---

### ETH Handling and Overpayment Loss (ref: fv-sol-6)

**Protocol-Specific Preconditions**

The contract accepts raw ETH via `payable` functions for NFT order execution. Pricing is dynamic (Dutch auction or reverse Dutch auction), making exact payment amounts unpredictable at submission time. The same function handles both ETH and ERC-20 payment paths without rejecting `msg.value > 0` on the ERC-20 path. A rescue or withdrawal function exists but mistakenly operates on `msg.value` of the rescue call rather than `address(this).balance`.

**Detection Heuristics**

- Identify `payable` functions that check `msg.value >= price` but do not refund `msg.value - price`.
- Check all ETH rescue or fee-withdrawal functions: verify they use `address(this).balance`, not `msg.value`.
- For functions supporting both ETH and ERC-20 currencies, verify that the ERC-20 path explicitly requires `msg.value == 0`.
- In auction contexts, estimate the maximum spread between submitted ETH and final price to quantify exposure.

**False Positives**

- The contract enforces exact ETH amounts and reverts on overpayment (no dynamic pricing).
- Separate functions exist for ETH and ERC-20 paths with no shared `payable` entry point.
- A WETH wrapping pattern is used throughout, eliminating raw ETH handling.
- The rescue function correctly references `address(this).balance`.

**Notable Historical Findings**

The Infinity NFT Marketplace contained three ETH-handling failures reported together. Overpayment on `takeOrders` was silently accepted without refund. The `rescueETH` function sent `msg.value` from the rescue call itself rather than the contract's accumulated balance, leaving all protocol fees permanently locked. A third path allowed ETH to be sent alongside ERC-20 orders with no rejection, causing the ETH to be irrecoverably trapped in the contract.

**Remediation Notes**

After computing the total price for an order, calculate and refund the excess: `if (excess > 0) msg.sender.call{value: excess}("")`. Require `msg.value == 0` on all ERC-20 execution paths. Implement `rescueETH` as a non-`payable` function that sends `address(this).balance` to the destination.

---

### Irrevocable Privileged Roles (ref: fv-sol-4)

**Protocol-Specific Preconditions**

The contract uses role-based access control (custom mapping or OpenZeppelin `AccessControl`) but provides functions only to grant roles, not revoke them. `DEFAULT_ADMIN_ROLE` is never assigned in the constructor, preventing governance over role assignment. Boolean permission mappings are only set to `true` with no mechanism to restore `false`. The deprecated `_setupRole` is used instead of `_grantRole`, bypassing the admin system.

**Detection Heuristics**

- For every `addX` or `setAllowed` function that grants a role or sets a permission to `true`, check whether a corresponding revocation function exists.
- In `AccessControl` contracts, verify that `DEFAULT_ADMIN_ROLE` is granted to an appropriate address during construction.
- Search for `_setupRole` usage; it is deprecated and does not propagate admin relationships correctly.
- Check permission mappings for write-only `true` assignments with no matching `false` path.

**False Positives**

- The contract is intentionally immutable and roles are assigned once at deployment with no operational need for revocation.
- A proxy or upgrade pattern allows role corrections via an upgrade transaction.
- `DEFAULT_ADMIN_ROLE` is properly assigned and the standard `revokeRole` interface is accessible.
- A governance timelock can force role changes through proposals.

**Notable Historical Findings**

In the AI Arena contracts, `Neuron` (the ERC-20 token) exposed `addMinter`, `addStaker`, and `addSpender` functions but no corresponding removal functions. The `DEFAULT_ADMIN_ROLE` was never granted, so even the owner could not revoke roles through the `AccessControl` interface. The `GameItems` contract had a `setAllowedBurningAddresses` function that wrote `true` to a mapping but provided no way to revoke burning access once granted. A separate finding in OnchainHeroes documented a case where a missing access check on a burn function allowed unauthorized token destruction.

**Remediation Notes**

Grant `DEFAULT_ADMIN_ROLE` to the owner in the constructor and use `_grantRole`/`revokeRole` throughout. Replace one-directional `addX` functions with toggle functions accepting an `bool access` parameter. Replace all `_setupRole` calls with `_grantRole`.

---

### Admin Timelock and Recovery Abuse (ref: fv-sol-4)

**Protocol-Specific Preconditions**

The contract has admin-controlled recovery functions gated by a timelock. The timelock is anchored to contract initialization rather than to the relevant game event (e.g., draw completion). Time constants are calculated incorrectly, skewing the intended duration. Admin-changeable parameters (fees, gas cost multipliers) apply retroactively to existing orders with no upper bound.

**Detection Heuristics**

- Check what event anchors recovery timelocks; verify that the anchor is updated when the event recurs (e.g., each new draw resets the recovery window).
- Audit constant time-unit calculations manually: `(3600 * 24 * 7) * 30` produces a 7-month value, not a 1-month value.
- For every admin-settable parameter (fees, gas units, thresholds), verify an upper bound exists and that changes do not retroactively affect in-flight orders.
- Check if admin can block required protocol functions (e.g., refusing to fund VRF subscription, not calling `startDraw`).

**False Positives**

- The admin is a DAO or multisig with a transparent governance process and its own timelock.
- Parameter changes only apply to newly created orders or future rounds.
- Upper bounds on all changeable parameters prevent economically meaningful exploitation.

**Notable Historical Findings**

In the Forgeries raffle protocol, the `lastResortTimelockOwnerClaimNFT` function allowed the draw organizer to reclaim the escrowed NFT after a cooldown anchored to contract initialization, not draw completion. Because the draw could be started well after deployment, the organizer could claim the NFT before any draw result was finalized. A separate constant bug in the same protocol produced a `MONTH_IN_SECONDS` value seven times larger than intended because the weekly multiplier was applied to the monthly calculation. The Infinity NFT Marketplace had `updateWethTransferGas` with no upper bound, allowing the owner to inflate gas costs charged to buyers arbitrarily.

**Remediation Notes**

Reset the recovery timelock inside `fulfillRandomWords` or the equivalent draw-completion callback, not at initialization. Compute time constants using base units: `(3600 * 24) * 30` for one month. Cap all admin-settable parameters and consider a commit-delay before parameter changes take effect for values that affect existing orders.

---

### Incomplete Transfer Restriction Bypass (ref: fv-sol-5)

**Protocol-Specific Preconditions**

Custom transfer restrictions are implemented by overriding only a subset of transfer functions in an ERC-721 or ERC-1155 base contract. ERC-721 exposes three public transfer entry points; ERC-1155 exposes `safeTransferFrom` and `safeBatchTransferFrom`. Tokens have protocol-meaningful transfer-blocking properties such as staking locks, non-transferability flags, or in-game state dependencies.

**Detection Heuristics**

- For ERC-721 contracts with custom transfer checks, confirm all three variants are overridden: `transferFrom`, `safeTransferFrom(address,address,uint256)`, and `safeTransferFrom(address,address,uint256,bytes)`.
- For ERC-1155, confirm `safeBatchTransferFrom` is overridden with the same restriction logic as `safeTransferFrom`.
- Prefer audit via `_beforeTokenTransfer` / `_update` hooks, which intercept all transfer paths from a single override point.
- Check whether any staking or lock state is maintained in a separate mapping and verify it is checked on all transfer paths.

**False Positives**

- `_beforeTokenTransfer` or `_update` hooks are used (these intercept all transfer variants).
- The base contract only exposes one transfer function.
- Transfer restrictions are purely cosmetic and do not affect protocol invariants or game state.

**Notable Historical Findings**

In the AI Arena audit, `FighterFarm` overrode `transferFrom` and the three-argument `safeTransferFrom` with an `_ableToTransfer` check but left the four-argument `safeTransferFrom(address,address,uint256,bytes)` inherited and unchecked, allowing locked fighters to be transferred freely. A second finding on the same codebase showed that `GameItems` overrode `safeTransferFrom` to enforce a `transferable` flag but omitted an override for `safeBatchTransferFrom`, so non-transferable items could be moved in batch without restriction. A third variant showed that the daily allowance replenishment check could be bypassed by using `safeTransferFrom` with an alias account.

**Remediation Notes**

Override `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) instead of individual public functions; this single hook intercepts every transfer path including future standard extensions. If individual overrides are unavoidable, maintain a checklist against the base contract's full interface and add a CI test that calls each variant.

---

### NFT Transfer Standard Interface Confusion (ref: fv-sol-5)

**Protocol-Specific Preconditions**

The contract handles transfers of NFTs that may implement ERC-721, ERC-1155, or both simultaneously. Interface detection via `supportsInterface` selects the transfer path. The dispatch logic falls through silently when no recognized interface is detected. Some production NFT collections (e.g., The Sandbox ASSET token) implement both ERC-721 and ERC-1155, triggering the wrong dispatch branch when ERC-721 is checked first.

**Detection Heuristics**

- Verify that a `revert` is present when neither `0x80ac58cd` (ERC-721) nor `0xd9b67a26` (ERC-1155) is detected; silent return on an unrecognized collection means buyer pays but receives nothing.
- Check the priority of interface checks: ERC-1155 should be checked before ERC-721 for dual-standard tokens.
- Confirm that `numTokens` from ERC-1155 orders is respected if execution falls into the ERC-721 path.
- Verify that duplicate token IDs within the same collection are detected and rejected to prevent inflated order quantities.

**False Positives**

- The contract maintains a whitelist of supported collections validated at order creation.
- The fallthrough case contains an explicit `revert`.
- The marketplace explicitly documents that dual-standard tokens are unsupported and enforces this with a collection registry.

**Notable Historical Findings**

The Infinity NFT Marketplace checked for ERC-721 support before ERC-1155, so a dual-standard token (a real category in production) would always enter the ERC-721 path and discard quantity information. A separate finding showed that the dispatch returned without reverting when neither interface was detected, meaning payments were settled and sellers received proceeds while buyers received no NFTs. A third variant demonstrated that the `canExecTakeOrder` matching function could be bypassed by supplying duplicate token IDs, allowing inflated order sizes to be validated.

**Remediation Notes**

Check ERC-1155 before ERC-721 in all dispatch logic to handle dual-standard tokens correctly. Always add a terminal `revert("Unsupported NFT standard")` branch. Validate that token ID arrays contain no duplicates within a single collection before executing any order.

---

### Order Matching Validation Gaps (ref: fv-sol-5)

**Protocol-Specific Preconditions**

An NFT marketplace matches buy orders with sell orders, either on-chain or via an off-chain engine. Order matching logic validates token count, price, and intersection but allows empty `tokenIds` arrays, omits a `seller != buyer` check, or measures item count against buy-order constraints rather than the number of items being actually constructed and transferred.

**Detection Heuristics**

- Trace order execution end-to-end and verify that the final transfer count equals the validated item count.
- Check whether an empty `tokens` array on either side of an order causes `doItemsIntersect` to return `true` (wildcard semantics can satisfy intersection without any actual transfer).
- Verify that `seller != buyer` is enforced in all matching paths; its absence enables self-matching exploits such as wash trading or fee farming.
- Confirm that the Complication contract is consulted on every execution path, including convenience entry points like `takeMultipleOneOrders`.
- Validate that `numConstructedItems` (the count of tokens actually dispatched) is checked against both buy and sell constraints, not only one side.

**False Positives**

- The off-chain matching engine validates all orders before submission and only submits fully specified, non-duplicate orders.
- The protocol exclusively supports fixed-price, fully-specified orders with no wildcard semantics.
- A single canonical matching function handles all paths and is exhaustively validated.

**Notable Historical Findings**

In Infinity NFT Marketplace, a buyer with an empty `tokens` array could have their order fulfilled: the intersection check returned true (wildcards match anything), and the item count check compared against the buy-order constraint rather than the actual transfer count, so the buyer paid but received no NFTs. A second finding showed that omitting a `seller != buyer` check allowed an actor to match their own orders, enabling wash trading and draining protocol fees. A third path, `takeMultipleOneOrders`, skipped the Complication contract check entirely, bypassing all order validation logic.

**Remediation Notes**

Require `tokenIds.length > 0` for all order entries before executing any transfer. Enforce `sell.signer != buy.signer` across all matching entry points. Validate `numConstructedItems` against both buy and sell constraints, not just one. Audit all execution entry points to ensure the Complication contract is invoked on each.

---

### Raffle and Randomness Manipulation (ref: fv-sol-5-c11)

**Protocol-Specific Preconditions**

The contract uses Chainlink VRF or similar oracle randomness for draw outcomes. The draw organizer controls VRF subscription funding and can trigger redraws before the oracle responds. Alternatively, attribute generation is deterministic and occurs within the same transaction as minting, allowing contract-wallet recipients to observe and selectively revert unfavorable results via `onERC721Received`.

**Detection Heuristics**

- Check whether the VRF subscription is funded or controlled by the same entity that can initiate redraws; this creates a selective-abort capability.
- Verify that the minimum redraw cooldown exceeds the maximum Chainlink VRF pending time (24 hours for V2 under normal network conditions).
- Identify minting functions where attribute determination and `_safeMint` occur in the same transaction with no commit-reveal separation.
- Scan for on-chain entropy sources (`block.timestamp`, `block.prevrandao`, `msg.sender`, `blockhash`) used as the sole randomness input.
- Check whether a pending VRF request can be superseded by a new request before `fulfillRandomWords` is called.

**False Positives**

- The VRF subscription is funded by a trusted third party or the protocol treasury with adequate pre-committed balance.
- The redraw cooldown is greater than 24 hours, exceeding the maximum VRF pending window.
- Attribute generation uses a separate commit-reveal or delayed oracle callback, not the mint transaction.
- `_mint` rather than `_safeMint` is used, eliminating the callback revert vector.

**Notable Historical Findings**

In the Forgeries raffle protocol, the draw organizer controlled the VRF subscription funding and held the power to call `redraw`. By withholding subscription funds until observing an unfavorable pending VRF response, or by calling `redraw` just before `fulfillRandomWords` executed (invalidating the current request ID), the organizer could selectively abort draws that would produce unwanted winners. In AI Arena, fighter attributes were generated deterministically from a hash of sender and token ID within the same transaction as `_safeMint`, so a contract wallet could check the resulting attributes inside `onERC721Received` and revert the entire transaction to retry for desired traits.

**Remediation Notes**

Separate attribute assignment from minting: mint first with `_mint` (no callback), then fulfill attributes in the VRF callback. Set the minimum redraw cooldown to strictly greater than 24 hours and enforce it on-chain. Ensure the VRF subscription is funded by the protocol, not the draw organizer, or use a pull-funding model where the subscription cannot be drained selectively.

---

### Unbounded Loop DoS in Reward Claims (ref: fv-sol-9)

**Protocol-Specific Preconditions**

A reward claiming function iterates from the user's last-claimed round to the current round with no upper bound per transaction. The loop contains nested iterations (e.g., scanning all winners per round) or non-trivial per-iteration cost (storage reads, external calls, minting). The protocol can advance many rounds without requiring user participation, allowing the gap to grow until a future claim hits the block gas limit.

**Detection Heuristics**

- Identify claim functions with a loop bounded by `currentRound < roundId` or `currentEpoch < epochId` where the gap is user-controlled (infrequent claimers).
- Estimate gas cost per round iteration: a single SLOAD costs 2100 gas; an external mint call costs 20k+. Compute the round count at which the block gas limit is reached.
- Check for nested loops (rounds × winners per round) which create quadratic gas growth.
- Verify whether the protocol can advance rounds without any user interacting (keeper-triggered advancement).

**False Positives**

- The total number of rounds is strictly bounded and small enough that worst-case gas is below the block gas limit.
- Per-iteration gas cost is minimal (only memory operations) and the protocol enforces regular claiming.
- Users are required to claim every round by protocol design, preventing accumulation.
- An off-chain keeper claims for all users periodically, preventing gaps from forming.

**Notable Historical Findings**

In AI Arena, both `claimRewards` in the MergingPool and `claimNRN` in RankedBattle iterated over all unclaimed rounds since the user's last claim. The `claimRewards` function contained a nested loop scanning all winners per round, making gas cost proportional to `rounds × winners`. Because rounds advanced on a fixed schedule regardless of user activity, a user who skipped many rounds could permanently lose the ability to claim their rewards. Separately in OnchainHeroes Fishingvoyages, an uninitialized `stakeDuration` allowed users to bypass the intended fishing lock duration and unstake immediately.

**Remediation Notes**

Add a `totalRoundsToConsider` parameter allowing users to claim in bounded batches, with a check that `lowerBound + totalRoundsToConsider <= roundId`. Alternatively, track accumulated rewards per user in a rolling mapping updated at round advancement (push model), eliminating the need for per-round iteration at claim time.

---

### Uninitialized State Variable Exploits (ref: fv-sol-5)

**Protocol-Specific Preconditions**

Critical state variables are set by admin setter functions after deployment rather than in the constructor. Functions depending on these variables do not check for zero/uninitialized values before use. Default zero values bypass time-lock checks (duration of zero means the lock has already expired), cause division-by-zero panics for uninitialized modular arithmetic divisors, or grant incorrect defaults. Mappings are partially initialized (e.g., only for generation zero), leaving subsequent generations with zero values.

**Detection Heuristics**

- Enumerate all state variables written by post-deployment setter functions and verify that consuming functions guard against uninitialized (zero) values.
- Look for duration or cooldown checks of the form `block.timestamp < stakeAt + stakeDuration` where `stakeDuration == 0` makes the condition trivially false.
- Scan for `% denominator` operations where `denominator` is a mapping value that may not be initialized for all keys.
- Verify that the deployment/initialization sequence is atomic or that the contract is paused until configuration is complete.

**False Positives**

- All required state variables are initialized in the constructor or in an `initializer` function called atomically in the deployment transaction.
- A factory contract handles initialization in the same transaction as deployment.
- The contract is paused by default and only unpaused after admin configuration is complete.
- An `initializer` modifier from a proxy pattern ensures all variables are set before the contract is operational.

**Notable Historical Findings**

In the OnchainHeroes Fishingvoyages contract, `stakeDuration` was left at zero after deployment. The unstaking check `block.timestamp < stakeAt + stakeDuration` always evaluated to false when `stakeDuration == 0`, so users could unstake immediately regardless of the intended fishing duration. In AI Arena's `FighterFarm`, `numElements` was only set in the constructor for generation zero; any fighter creation for subsequent generations triggered a division-by-zero panic because the divisor for the element calculation was uninitialized, making generation advancement non-functional.

**Remediation Notes**

Add zero-value guards to all functions that depend on post-deployment configuration: `if ($.stakeDuration == 0) revert NotInitialized()`. When incrementing game state (e.g., generation), initialize all dependent mappings for the new state in the same transaction. Consider a two-phase deployment pattern where the contract begins in a paused state and a single initialization transaction sets all required values before unpausing.

---

### Unvalidated User-Supplied NFT Attributes (ref: fv-sol-5)

**Protocol-Specific Preconditions**

NFT minting or re-roll functions accept user-controlled parameters (fighter type, element, weight, DNA, custom attributes) that directly determine token traits. Trait generation is deterministic: the same inputs always produce the same outputs. Type-specific limits (e.g., max re-rolls per fighter type) are enforced using the user-supplied type rather than the on-chain type of the token. The resulting traits affect in-game mechanics, rarity, or economic value.

**Detection Heuristics**

- Identify all minting and re-roll functions that accept user-controlled parameters influencing attributes.
- Check whether `fighterType` or equivalent type discriminators are validated against the actual on-chain state of the token being modified.
- Verify that numeric attribute ranges (element, weight, generation-specific bounds) are validated with explicit `require` statements before use.
- For mint-pass or claim-based minting, check whether a server-side signature is required to authorize the specific attribute set, or whether users can supply arbitrary values.
- Determine whether the same DNA or attribute input always produces the same output, making brute-force or revert-based selection trivially feasible.

**False Positives**

- Attribute generation uses Chainlink VRF with commit-reveal, making the output unpredictable at mint time.
- All user-supplied inputs are validated against expected ranges and cross-checked against on-chain token state.
- A trusted backend signature is required to authorize the attribute set for each mint or re-roll.
- Attributes are purely cosmetic and do not affect game mechanics or token value.

**Notable Historical Findings**

In AI Arena, the `reRoll` function accepted a user-supplied `fighterType` parameter and used it to look up `maxRerollsAllowed[fighterType]` without verifying that the supplied type matched the actual type of the token being re-rolled. A Dendroid token owner could pass `fighterType = 0` to circumvent the Dendroid re-roll limit and apply champion-type generation logic. The `redeemMintPass` function allowed callers to freely specify `fighterType` and copy DNA strings from existing rare fighters, enabling on-demand production of high-rarity tokens. A third variant showed that `mintFromMergingPool` accepted `customAttributes` as a raw two-element array with no range validation, allowing callers to assign any element or weight to a newly minted fighter.

**Remediation Notes**

Validate `fighterType` against the token's on-chain `dendroidBool` field before applying any type-specific logic. Enforce explicit range checks on all numeric attributes at the point of minting and re-rolling. Require a server-signed message authorizing the specific attribute set for any mint function where the caller supplies trait inputs; this prevents brute-force selection by making the authorized output opaque until claim time.

### ERC721Consecutive Balance Corruption with Single-Token Batch (ref: pashov-2)

**Protocol-Specific Preconditions**

The gaming or NFT contract inherits OpenZeppelin `ERC721Consecutive` and calls `_mintConsecutive(to, 1)` to mint individual tokens during a batch or claim phase. The contract runs on a version of OpenZeppelin prior to 4.8.2. Downstream game logic, access control, or marketplace integrations rely on `balanceOf` to determine ownership status or gate game actions.

**Detection Heuristics**

- Locate all `_mintConsecutive` call sites and check whether any call with a batch size of 1 exists.
- Confirm the OpenZeppelin library version in `package.json` or `foundry.toml`; any version below 4.8.2 is affected.
- Check whether any downstream function (`balanceOf`, `tokensOfOwner`, or similar) is used to gate game mechanics or reward eligibility.
- If batch minting is mixed with single-token claims, verify the code paths use different base minting functions for the two cases.

**False Positives**

- The contract uses OpenZeppelin version 4.8.2 or later, which patches this behavior.
- All batch mints use a minimum size of 2 tokens.
- The contract uses standard `ERC721._mint` rather than `ERC721Consecutive._mintConsecutive`.
- No game or protocol logic depends on `balanceOf` returning a correct value immediately after minting.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Upgrade to OpenZeppelin 4.8.2 or later. When a batch size of 1 is a valid use case, use the standard `_mint` function rather than `_mintConsecutive`, as the consecutive batch mechanism requires at least two tokens to correctly increment the balance mapping.

---

### Missing onERC1155BatchReceived Causes Token Lock (ref: pashov-14)

**Protocol-Specific Preconditions**

A gaming contract holds or receives ERC-1155 tokens representing in-game items, equipment, or currencies. The contract implements `onERC1155Received` to handle individual transfers but does not implement `onERC1155BatchReceived`, or its implementation returns an incorrect selector. Settlement, reward distribution, or bulk crafting operations use `safeBatchTransferFrom` to send multiple item types in one transaction.

**Detection Heuristics**

- Search for `onERC1155Received` implementations and verify whether `onERC1155BatchReceived` is also present and returns `this.onERC1155BatchReceived.selector`.
- Check whether the contract inherits `ERC1155Holder` from OpenZeppelin, which implements both callbacks correctly.
- Identify all code paths that call `safeBatchTransferFrom` toward this contract; any such call will revert if the batch callback is missing or incorrect.
- Verify the return value of `onERC1155BatchReceived` equals `0xbc197c81` rather than a custom or hardcoded value.

**False Positives**

- The contract inherits OpenZeppelin `ERC1155Holder`, which provides both callbacks with correct selectors.
- The protocol exclusively uses single-item `safeTransferFrom` and never calls `safeBatchTransferFrom` toward this contract.
- The contract is itself an ERC-1155 token contract, which inherits the batch receiver interface by default.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Inherit `ERC1155Holder` from OpenZeppelin rather than implementing receiver callbacks manually. If implementing callbacks manually, verify both `onERC1155Received` and `onERC1155BatchReceived` are present and return their respective correct selectors (`0xf23a6e61` and `0xbc197c81`).

---

### ERC1155 URI Missing id Substitution (ref: pashov-19)

**Protocol-Specific Preconditions**

The contract implements ERC-1155 `uri(uint256 id)` and returns a fully resolved, token-specific URL or a static base URL without the literal `{id}` placeholder required by EIP-1155. NFT metadata clients and marketplaces call `uri(id)` and expect to perform client-side substitution of the literal string `{id}` with the zero-padded hexadecimal token ID. A static or fully resolved return collapses distinct tokens to a single metadata record or causes parsing failures.

**Detection Heuristics**

- Read the `uri()` implementation and verify the returned string contains the literal substring `{id}`.
- If the contract returns a per-ID resolved URL, verify this is explicitly documented as a deviation from EIP-1155's substitution-based metadata standard.
- Check whether `uri()` returns an empty string for any valid token ID, which causes metadata to be unavailable.
- Confirm that marketplaces and game frontends integrating with this contract are tested against the actual `uri()` output format.

**False Positives**

- The contract returns a string containing the literal `{id}` placeholder per EIP-1155 specification.
- Per-ID on-chain metadata is returned directly and the deviation from the substitution standard is explicitly documented in the interface specification.
- The contract is intentionally off-specification and all downstream clients are built to handle the custom format.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Return a string containing the literal `{id}` substring as required by EIP-1155: for example, `"https://game.example/metadata/{id}.json"`. Clients will substitute the lowercase hex representation of the token ID, zero-padded to 64 characters. If per-ID resolution is needed on-chain, document the deviation and verify all consuming clients handle it explicitly.

---

### ERC1155 Fungible and Non-Fungible Token ID Collision (ref: pashov-65)

**Protocol-Specific Preconditions**

The gaming contract uses a single ERC-1155 deployment to represent both fungible resources (currencies, consumables) and unique items (characters, legendary equipment) under different token IDs. No enforcement exists at the contract level to prevent minting additional copies of an ID intended to be supply-1. Multiple mintings to different users for the same NFT-designated ID are possible.

**Detection Heuristics**

- Identify all mint functions and check whether they enforce `require(totalSupply(id) + amount <= maxSupply(id))` or equivalent before minting.
- For IDs designated as unique items, verify `maxSupply[id] == 1` is set and enforced.
- Check whether fungible and non-fungible ID ranges are disjoint by design and whether the boundary is validated in mint functions.
- Verify that role or access tokens represented as ERC-1155 IDs are non-transferable if their uniqueness underpins access control.

**False Positives**

- `require(totalSupply(id) + amount <= maxSupply(id))` is enforced with `maxSupply = 1` for all NFT-designated IDs.
- Fungible and non-fungible token IDs occupy explicitly separated and enforced ranges.
- Role tokens are non-transferable via an override in `_beforeTokenTransfer` that reverts on non-mint/burn operations.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Define an immutable maximum supply per token ID at mint time using a `maxSupply[id]` mapping set in a single authorized function. Enforce `require(totalSupply(id) + amount <= maxSupply[id])` in all mint paths. For NFT IDs, set `maxSupply[id] = 1` and verify this is set before any mint of that ID can occur. Separate ID namespaces for fungible and non-fungible tokens using explicit range checks.

---

### ERC721Enumerable Index Corruption on Burn or Transfer (ref: pashov-81)

**Protocol-Specific Preconditions**

The gaming contract inherits `ERC721Enumerable` for on-chain enumeration of token ownership (for example, to list all fighters, characters, or items owned by an address). A custom override of `_beforeTokenTransfer` (OpenZeppelin v4) or `_update` (OpenZeppelin v5) is present for game logic such as attribute updates, staking locks, or cooldown enforcement. The override does not call `super._beforeTokenTransfer` or `super._update` as its first statement, preventing the enumerable index from being updated on transfer or burn.

**Detection Heuristics**

- Find all `_beforeTokenTransfer` and `_update` overrides in contracts inheriting `ERC721Enumerable`. Verify each calls `super._beforeTokenTransfer(from, to, tokenId, batchSize)` or `super._update(to, tokenId, auth)` before any other logic.
- After simulating a transfer or burn, verify `tokenOfOwnerByIndex(previousOwner, ...)` no longer returns the transferred token ID.
- Check that `totalSupply()` decrements correctly after a burn operation.
- Verify that `_ownedTokens` and `_allTokens` are consistent after a sequence of mint, transfer, and burn operations.

**False Positives**

- The contract's override unconditionally calls `super` as its first statement.
- The contract does not inherit `ERC721Enumerable` and uses an alternative enumeration mechanism.
- The override is only reached on mint paths and the enumerable data structures are independently correct for transfer and burn.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Place `super._beforeTokenTransfer(from, to, tokenId, batchSize)` (or `super._update(to, tokenId, auth)` in OZ v5) as the unconditional first statement of any override. Never rely on compiler-enforced super call ordering in multi-inheritance graphs; be explicit. Add integration tests that verify `tokenOfOwnerByIndex`, `tokenByIndex`, and `totalSupply` return consistent values after a full sequence of mint, transfer, and burn operations.

---

### ERC721A Lazy Ownership Uninitialized in Batch Range (ref: pashov-116)

**Protocol-Specific Preconditions**

The gaming contract uses ERC721A or `ERC721Consecutive` for gas-efficient batch minting, which writes ownership for only the first token in a minted batch and lazily resolves subsequent token IDs by scanning backward. Access control logic elsewhere in the game checks `nft.ownerOf(tokenId) == msg.sender` for freshly minted tokens in the middle of a batch range. Before any transfer of a mid-batch token, `ownerOf` may return `address(0)` depending on implementation version, causing the access check to fail.

**Detection Heuristics**

- Identify all `ownerOf(tokenId) == msg.sender` or `ownerOf(tokenId) == address(0)` checks on contracts using ERC721A or `ERC721Consecutive`.
- Verify whether `ownerOf` is called on tokens immediately after a batch mint without an intervening transfer that would initialize the packed slot.
- Check whether the contract's ERC721A version resolves mid-batch ownership correctly or requires a transfer to trigger lazy initialization.
- Test access control functions with token IDs in the middle of a batch range that have never been transferred.

**False Positives**

- The contract uses standard OpenZeppelin `ERC721`, which writes `_owners[tokenId]` individually per mint.
- An explicit transfer or initialization step is always called before any `ownerOf`-dependent logic executes.
- The ERC721A version used correctly resolves mid-batch ownership through its backward scan without returning `address(0)`.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

When using ERC721A or `ERC721Consecutive`, avoid relying on `ownerOf` returning correct values for mid-batch tokens before any transfer has occurred. Use the explicit packed ownership initialization provided by ERC721A if per-token ownership reads are needed immediately post-mint. For access control over freshly minted tokens, read the batch owner from the minting record rather than querying `ownerOf` per token ID.

---

### NFT Staking Records msg.sender Instead of ownerOf (ref: pashov-126)

**Protocol-Specific Preconditions**

An NFT staking contract records the depositor for each staked token using `depositor[tokenId] = msg.sender` without verifying that `msg.sender` is the actual owner. The NFT transfer succeeds because `msg.sender` holds operator approval for the owner, but the depositor mapping credits the operator rather than the owner. Reward claims, unstaking rights, and in-game privileges are tied to the depositor mapping.

**Detection Heuristics**

- Find all staking deposit functions that call `nft.transferFrom(msg.sender, address(this), tokenId)` or `nft.safeTransferFrom` and then assign `depositor[tokenId] = msg.sender`.
- Check whether `nft.ownerOf(tokenId)` is read before the transfer and used as the depositor rather than `msg.sender`.
- Verify that approved operators (non-owners) cannot call the deposit function and be credited as the depositor.
- Test the deposit function when called from an approved-but-not-owner address to confirm the recorded depositor is the actual token owner.

**False Positives**

- The deposit function includes `require(nft.ownerOf(tokenId) == msg.sender)`, preventing non-owners from staking.
- The deposit function reads `nft.ownerOf(tokenId)` before the transfer and stores that address rather than `msg.sender`.
- The staking contract is designed to allow operator deposits and credits the operator intentionally for protocol-specific reasons.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Replace `depositor[tokenId] = msg.sender` with `depositor[tokenId] = nft.ownerOf(tokenId)` called before the transfer executes, or add `require(nft.ownerOf(tokenId) == msg.sender)` to prevent approved operators from initiating deposits on behalf of owners. The latter approach is stricter and eliminates the operator deposit path entirely.

---
