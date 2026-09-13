# NFT Marketplace Security Patterns

> Applies to: NFT marketplaces, order book marketplaces, Seaport-style, LooksRare-style, Blur-style, on-chain NFT auctions, NFT lending markets, ERC-721/ERC-1155 trading protocols

## Protocol Context

NFT marketplaces combine off-chain order signing with on-chain settlement, meaning the on-chain execution layer must rigorously validate maker/taker signatures, nonces, and order parameters that were assembled in a context the contract never controlled. The use of `safeTransferFrom` on ERC-721 and ERC-1155 tokens introduces reentrancy vectors through `onERC721Received` and `onERC1155Received` callbacks, which fire mid-settlement before order state is finalized. Royalty enforcement, excess ETH refund patterns, ERC-1155 quantity accounting, and support for non-standard tokens like CryptoKitties each introduce protocol-specific correctness requirements not present in simpler token contracts.

## Bug Classes

### Reentrancy via NFT Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**

- Settlement calls `safeTransferFrom` on ERC-721 or ERC-1155 tokens before marking order nonces as used
- Fee distribution functions invoke receiver callbacks (`receiveRewards`) between token transfers
- DAO quit or rage-quit functions perform ERC20 transfers using ERC-777 tokens that trigger callbacks mid-loop
- Cross-contract reentrancy is possible when token accounting state is shared between a vault and a logic contract

**Detection Heuristics**

- Audit every `safeTransferFrom` call site and confirm nonce/state updates precede it
- Search for fee distribution loops that call external `receiveRewards`-style hooks between balance reads and transfers
- Check `quit()`/`ragequit()` patterns for `totalSupply` reads followed by external ERC20 transfers before burns complete
- Verify `nonReentrant` is applied to all settlement entry points, not just the outermost dispatcher

**False Positives**

- When `nonReentrant` is applied to all entry points of the contract and state updates strictly precede interactions
- When the only external call is to WETH or another known non-reentrant token
- When read-only reentrancy has no influence on settlement math or invariants

**Notable Historical Findings**

Infinity NFT Marketplace had a reentrancy path through `matchOneToManyOrders` where ERC-721 `safeTransferFrom` triggered an attacker-controlled `onERC721Received` callback before the maker's nonce was marked used, allowing the same order to be re-settled. NFTX's fee distributor called `receiveRewards` on each fee receiver mid-loop without a reentrancy guard, enabling a malicious receiver to reenter `distribute` and collect fees multiple times from the same vault balance snapshot. Nouns DAO's `quit()` function was vulnerable to cross-contract reentrancy through ERC-777 token callbacks between the `totalSupply` read and burn operations.

**Remediation Notes**

Apply the checks-effects-interactions pattern strictly: mark nonces used and burn tokens before any transfer. Add `nonReentrant` to all settlement, distribution, and quit entry points. For DAO treasury distributions, complete all burns before iterating over ERC20 transfers.

---

### Signature Validation and Replay (ref: fv-sol-4-c4, fv-sol-4-c10, fv-sol-4-c11)

**Protocol-Specific Preconditions**

- Order signatures are created off-chain and validated on-chain via `ecrecover` or `ECDSA.recover`
- EIP-712 domain separator is computed once in the constructor and caches `block.chainid`
- Signed messages do not include a nonce, expiry, or the domain separator is not recomputed after a chain fork
- `delegateBySig` or custom permit-style functions do not enforce expiry or nonce invalidation

**Detection Heuristics**

- Search for direct `ecrecover` calls and confirm the return value is checked against `address(0)`
- Check all EIP-712 implementations for whether `DOMAIN_SEPARATOR` is a storage variable set at construction versus recomputed dynamically
- Look for `withdraw`, `delegate`, or `cancel` functions where the signed payload omits a nonce
- Verify the `v` parameter is validated to 27 or 28 and that `s` is in the lower-half of the secp256k1 order to block malleability

**False Positives**

- When OpenZeppelin `ECDSA.recover` is used throughout, as it checks for zero-address and malleability internally
- When OpenZeppelin `EIP712` base contract is used with `_domainSeparatorV4()`, which recomputes on chain fork
- When the protocol operates on a single finalized chain with no plans for multi-chain deployment

**Notable Historical Findings**

Golom's `validateOrder` passed the ecrecover return directly into an equality check against `o.signer` without a zero-address guard, allowing invalid signatures to authenticate against uninitialized order structs. Golom also hardcoded the chain ID in the domain separator at deploy time, making all signed orders replayable on forked networks. Taiko's `withdraw()` function signed over only the recipient and amount with no nonce, enabling the same signature to be submitted repeatedly to drain accumulated balance. Nouns DAO's `cancelSig` was incomplete due to signature malleability - a transformed `s` value produced a distinct bytes signature that the cancellation mechanism did not recognize.

**Remediation Notes**

Use OpenZeppelin `EIP712` and `ECDSA` exclusively. Nonces must be part of every signed payload and must be invalidated atomically with execution. For order-book marketplaces specifically, expiry timestamps should be mandatory fields in the order struct and validated before signature recovery.

---

### Order Validation and Matching Flaws (ref: fv-sol-8-c5)

**Protocol-Specific Preconditions**

- The matching engine accepts arrays of orders or items with no explicit uniqueness or self-match constraint
- Order validation logic compares wrong item arrays (e.g., raw order items vs. constructed settlement items)
- Gas reimbursement tied to order execution is calculated from measured `gasleft()` deltas per loop iteration
- Partial-fill tracking relies on nonce state that is only committed after a full batch completes

**Detection Heuristics**

- Confirm all matching functions enforce `makerOrder.signer != takerOrder.signer` (self-match prevention)
- Audit `canExecMatchOrder` and equivalent validators to confirm they compare the correct item arrays for each side
- Check gas refund mechanisms for position-dependency (first match in a batch paying different gas than subsequent ones)
- Verify that order nonces or fill counters are updated before external token transfers, not after

**False Positives**

- When self-matching is an explicit protocol feature documented for inventory management or testing
- When gas refund differences are bounded and explicitly acknowledged in the fee model
- When order validation is delegated to an audited external complication contract

**Notable Historical Findings**

Infinity NFT Marketplace did not prevent `seller == buyer` in any of its matching functions, enabling wash trading and fee manipulation through self-matched orders. A separate validation bug caused `canExecMatchOrder` to compare `sell.nfts` directly against `buy.nfts` rather than checking the constructed settlement items against both sides, rejecting valid orders. Golom's matching engine double-counted the protocol fee inside `_settleBalances`, reducing the taker payout by the fee amount twice, effectively stealing funds on every matched trade. Seaport's `executeMatchOrders` reverted when unused native tokens needed to be returned to the caller because no refund path was implemented for leftover ETH in matched order batches.

**Remediation Notes**

Enforce seller/buyer inequality as an explicit require at the top of all matching functions. Gas refunds should use a fixed per-match estimate, not live `gasleft()` measurement. Validate constructed settlement item arrays against both maker and taker order constraints, not the raw order fields against each other.

---

### ERC-1155 Quantity Accounting Errors (ref: no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

- Protocol supports ERC-1155 alongside ERC-721 and applies shared royalty or fee logic to both
- Royalty calculations divide total sale proceeds by `ids.length` rather than by total quantity transferred
- Order matching validates token ID sets for intersect without checking for duplicates across buyer and seller arrays
- Random selection from an ERC-1155 vault picks a token ID uniformly rather than weighting by deposited quantity

**Detection Heuristics**

- Search for royalty calculation functions that receive `uint256[] ids` and `uint256[] amounts` and check if `amounts` is actually used in the per-unit price derivation
- Look for order intersection checks that iterate `ids` arrays for equality without a nested uniqueness guard
- Audit random selection from vaults that store ERC-1155 holdings to confirm quantity-weighted sampling
- Check `safeBatchTransferFrom` call sites to confirm the `amounts` array matches actual quantities and not a constant `1`

**False Positives**

- When the protocol enforces that all ERC-1155 tokens are deposited with quantity exactly 1, effectively treating them as ERC-721
- When duplicate ID validation is performed in an upstream routing or validation layer before reaching the matching engine

**Notable Historical Findings**

NFTX's `_deductRoyalty1155` computed per-token sale price by dividing total proceeds by `ids.length`, completely ignoring the `amounts` array. Selling 100 units of a single token ID would massively overstate the per-unit sale price, causing royalty recipients to receive far more than owed and draining proceeds from sellers. Infinity NFT Marketplace's `doTokenIdsIntersect` had no duplicate ID check, allowing an attacker to include the same token ID multiple times in an order to steal additional NFTs during settlement. NFTX's `getRandomTokenIdFromFund` gave equal probability to every stored token ID regardless of deposited quantity, allowing an attacker to game vault redemptions toward higher-value IDs by controlling deposit ratios.

**Remediation Notes**

Royalty calculations for ERC-1155 must sum all quantities across IDs first, then compute per-unit price as `totalProceeds / totalQuantity` before calling `royaltyInfo` per token ID. Order matching must explicitly validate that no token ID appears more than once in either side of the trade.

---

### NFT Transfer Standard Compliance (ref: fv-sol-6-c9)

**Protocol-Specific Preconditions**

- Protocol uses `transferFrom` instead of `safeTransferFrom` for ERC-721 transfers, dropping the receiver callback check
- `safeTransferFrom` implementations validate receiver support via `supportsInterface` rather than by calling `onERC721Received` and verifying the return selector
- Protocol handles dual-standard tokens that implement both ERC-721 and ERC-1155 interfaces
- Non-standard NFTs (e.g., CryptoKitties) use custom transfer functions not conforming to EIP-721

**Detection Heuristics**

- Search for `IERC721(*.transferFrom(` call sites that should be `safeTransferFrom`
- Audit custom `safeTransferFrom` implementations for whether they call `onERC721Received` and compare the return value against `0x150b7a02`
- Identify NFT collections in scope that implement both `IERC721` and `IERC1155` interfaces and trace which branch of transfer logic is taken
- Check for hardcoded CryptoKitties address handling in multi-collection marketplace routers

**False Positives**

- When `transferFrom` is intentionally used to avoid callback reentrancy and the recipient is a known, trusted EOA or contract
- When the protocol explicitly restricts its supported collection set to exclude non-standard tokens

**Notable Historical Findings**

Infinity NFT Marketplace's `_transferNFTs` did not handle dual-standard tokens: collections implementing both ERC-721 and ERC-1155 would be processed by whichever interface was checked first, producing incorrect transfer semantics. NFTX's CryptoKitties-specific transfer path called `transferFrom(msg.sender, address(this), tokenId)` routing the NFT to the contract itself rather than to the intended recipient. Holograph implemented `safeTransferFrom` by calling `supportsInterface(onERC721Received.selector)` on the receiver rather than actually invoking the callback and checking its return value, making the safety check meaningless for contracts that do not self-declare that interface.

**Remediation Notes**

Use `safeTransferFrom` for all ERC-721 transfers to untrusted addresses. When implementing `safeTransferFrom` directly, call `IERC721Receiver(to).onERC721Received(...)` and assert the return value equals `IERC721Receiver.onERC721Received.selector`. For multi-standard tokens, check `IERC1155` interface support before `IERC721` to avoid ambiguous behavior.

---

### Excess ETH Not Refunded (ref: no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

- Payable settlement functions check `msg.value >= required` rather than `msg.value == required`
- Batch purchase functions accumulate total cost but do not refund the `msg.value - totalCost` remainder
- Cross-chain bridge fee estimation functions accept ETH, forward the exact fee to the bridge, and retain the surplus

**Detection Heuristics**

- Search for `payable` functions with `require(msg.value >= ...)` and confirm a refund path exists
- Audit batch execution loops: after the loop, verify that any ETH remainder is returned to `msg.sender`
- Look for `rescueETH` or admin-only ETH withdrawal functions - their presence signals awareness of the accumulation issue without actually fixing it for users
- Check bridge fee functions to ensure `msg.value - fee` is refunded after the bridging call

**False Positives**

- When excess ETH is explicitly documented as a voluntary tip to the protocol
- When `msg.value == exact` is enforced and overpayment reverts
- When a user-accessible refund function is available and the refund period is reasonable

**Notable Historical Findings**

Infinity NFT Marketplace's `fillAsk` accepted ETH with a `>=` check, meaning any overpayment by the buyer was permanently locked in the contract with no refund mechanism. Golom's `fillAsk` had the same pattern. Holograph's LayerZero module miscalculated the gas fee estimate passed to the bridge, causing callers to send more ETH than required and lose the excess to the contract. Taiko's `processMessage` allowed a malicious caller to pocket the bridge fee while forcing the guarded external call to fail by manipulating gas, combining excess ETH retention with a griefing vector.

**Remediation Notes**

After computing exact payment requirements, always return `msg.value - required` to `msg.sender` via a low-level call. Alternatively, enforce exact payment with `msg.value == required`. Never use a `rescueETH` admin function as a substitute for per-transaction refunds.

---

### Access Control and Privilege Escalation (ref: fv-sol-4)

**Protocol-Specific Preconditions**

- Factory-only or owner-only functions lack access control modifiers and are callable by any address
- Functions accepting a `from` address parameter combined with `transferFrom` allow arbitrary token drainage from approving users
- Admin role changes (ownership, operator, fee manager) occur in a single step without a two-step acceptance pattern
- Migration or burn functions during token upgrades do not restrict the `account` parameter to `msg.sender`

**Detection Heuristics**

- Search for `external` functions where NatSpec or naming implies a privileged caller but no modifier enforces it
- Identify `transferFrom(parameterAddress, ...)` call sites where the `from` address comes from a function argument
- Check admin role transfer functions for two-step acceptance patterns
- Audit fee assignment and protocol parameter functions for any caller being able to reset values to factory defaults

**False Positives**

- When access control is enforced at a trusted router or proxy layer and the implementation is intentionally unrestricted
- When the function is genuinely permissionless by design (e.g., anyone can trigger a keeper action)
- When the `from` parameter is validated against `msg.sender` or requires an explicit delegation before use

**Notable Historical Findings**

LooksRare had a function through which the protocol owner could call `transferFrom` with any user's address as the `from` parameter, draining any token balance approved to the contract. Reality Cards' `sponsor` function was intended to be callable only by the factory but had no modifier, allowing anyone to force arbitrary approved token holders to sponsor a market. NFTX's `assignFees` was callable by any address, enabling anyone to reset custom vault fee configurations back to factory defaults at will. NFTX's ERC-20 migration `burn` function accepted an arbitrary `account` parameter, allowing anyone to burn tokens held by a contract (such as an LP pool) and mint them to a new address.

**Remediation Notes**

Every function with a privileged intended caller must be enforced with an explicit modifier checked against a stored address. Functions that call `transferFrom` must never accept the `from` address as an unconstrained parameter. Ownership and role transfers must follow a two-step propose-and-accept pattern.

---

### Admin Centralization Risks (ref: fv-sol-4)

**Protocol-Specific Preconditions**

- Protocol fee rate or royalty configuration is controlled by a single EOA owner with no timelock
- Fee changes apply immediately to all existing unfilled orders, retroactively altering settlement economics
- No upper bound is enforced on fee parameters during owner-controlled updates
- Governance contracts lack deadlock recovery mechanisms

**Detection Heuristics**

- Search for `onlyOwner` functions that modify `protocolFeeRate`, `royaltyRate`, or equivalent and confirm timelock enforcement
- Check whether the owner address is a multisig or an EOA
- Identify governance parameter setters (`forkThresholdBPS`, `forkPeriod`, `voteSnapshotBlockSwitchProposalId`) that are not gated behind the full proposal lifecycle
- Verify that governance cannot enter a state where no proposal can pass (quorum/threshold deadlock)

**False Positives**

- When the owner is a Gnosis Safe with documented signer set and threshold
- When all parameter changes go through a timelocked governance module
- When the protocol is in a documented guarded launch phase with explicit centralization acknowledgment

**Notable Historical Findings**

Infinity NFT Marketplace allowed the owner to change the protocol fee rate at any time with no timelock and no cap, immediately affecting all outstanding orders whose signers had no recourse. Nouns DAO's `forkThresholdBPS` and `forkPeriod` were settable by the DAO admin outside the standard proposal flow, allowing a malicious DAO to prevent token holders from forking or force them to fork under unfavorable conditions. zkSync's governance module had no resolution path for proposal deadlocks, meaning the protocol could become permanently ungovernable under certain voting configurations.

**Remediation Notes**

Fee rate changes must go through a timelock of at least 48 hours with a published maximum cap enforced on-chain. All fork-related and governance-critical parameters must be modified only through the full proposal lifecycle, not through direct owner calls. Governance contracts should include a last-resort emergency path that does not rely on a single key.

---

### Governance Voting Manipulation (ref: fv-sol-5)

**Protocol-Specific Preconditions**

- NFT-based or token-weighted voting uses per-token checkpoints that can be overwritten rather than accumulated in same-block updates
- Delegation functions do not remove the delegated token from the previous delegatee's list before assigning to a new one
- Proposal creation allows signature aggregation from multiple signers without a snapshot-block threshold check
- Fork escrow mechanisms allow escrowed tokens to be used to manipulate treasury split calculations

**Detection Heuristics**

- Search for `_writeCheckpoint` implementations and confirm same-block updates accumulate rather than overwrite
- Audit `delegate` functions for removal of old delegatee state before writing new delegation
- Check `proposeBySigs` and equivalent for threshold validation at the proposal's snapshot block, not at submission time
- Verify that escrowed tokens in fork mechanisms cannot vote in the parent DAO simultaneously

**False Positives**

- When same-block checkpoint overwrite is correct because the protocol only cares about end-of-block state
- When delegation cleanup is handled by a lazy-delete garbage collection sweep with correct semantics

**Notable Historical Findings**

Golom's `_writeCheckpoint` overwrote the existing checkpoint when the block number matched instead of accumulating the delta, meaning multiple delegations in the same block would discard intermediate voting power state. Golom's `delegate` function did not remove the token from the old delegatee's index, leaving phantom voting power in the previous delegatee's balance indefinitely. Nouns DAO allowed any co-signer of a proposal created via `proposeBySigs` to cancel it unilaterally, enabling a single hostile co-signer to grief any multi-sig proposal. Changing `voteSnapshotBlockSwitchProposalId` in Nouns DAO mid-governance allowed double-counting of votes for proposals that spanned the switch boundary.

**Remediation Notes**

Same-block checkpoint updates must compute the delta and add it to the existing checkpoint value, not replace it. Delegation must atomically remove from the old delegatee and assign to the new one within a single transaction. Proposal cancellation by signers should be restricted to the original proposer or require a governance vote.

---

### Cross-Chain Bridge Message Integrity (ref: fv-sol-5)

**Protocol-Specific Preconditions**

- Bridge message status can be manipulated by a privileged watchdog role without requiring cryptographic proof of source-chain origin
- Failed L1-to-L2 transactions have no on-chain refund path for the ETH locked in the bridge
- Message recall for ERC-20 bridges returns tokens to `message.from` without verifying the recipient can receive tokens on the current chain
- Bridge fee estimation functions allow callers to supply more ETH than required with no refund

**Detection Heuristics**

- Check bridge watchdog functions that toggle message status (`SUSPENDED` / `NEW`) for whether any proof of source-chain signal is required
- Audit L2 transaction request functions for refund mechanisms covering failed L2 execution
- Look for `recallMessage` paths that transfer tokens to contract addresses that may lack receive functions on the recall chain
- Verify that all `processMessage` implementations validate the message hash against a merkle proof or signal service before execution

**False Positives**

- When the watchdog role is a multisig with hardware-secured keys and monitoring infrastructure
- When message verification relies on ZK proofs of source-chain state roots
- When the bridge only supports a fixed set of message types with known, bounded effects

**Notable Historical Findings**

Taiko's bridge watchdog could set a message status directly to `NEW` by first suspending then unsuspending an arbitrary hash it constructed, allowing it to forge messages that would be processed as legitimate by `processMessage`. A separate Taiko finding showed that a malicious `processMessage` caller could forward the bridge fee to themselves while forcing the protected `excessivelySafeCall` to fail by providing insufficient gas. zkSync's `Mailbox.requestL2Transaction` checked the deposit limit of the L1 WETH bridge instead of the actual depositor, allowing certain callers to bypass deposit caps. Multiple zkSync findings documented loss of ETH when L2 bootloader execution failed with no on-chain recovery mechanism.

**Remediation Notes**

All bridge message processing must require a merkle proof or signal service attestation against the source chain's finalized state root before changing message status. Failed L2 transactions must be claimable by the original sender via a proof-of-failure mechanism. Watchdog roles should be limited to suspension only, never to unsuspension without proof.

---

### Unsafe ERC-20 Token Transfers (ref: fv-sol-6)

**Protocol-Specific Preconditions**

- Protocol uses `IERC20.transfer()` or `IERC20.transferFrom()` directly on configurable or arbitrary token addresses
- Token set includes USDT or similar non-standard tokens that do not return a `bool`, causing `require(token.transfer(...))` to revert on success
- Protocol ignores the return value of `transferFrom`, silently accepting failed transfers as successful

**Detection Heuristics**

- Search for `.transfer(` and `.transferFrom(` calls on IERC20 interfaces not wrapped in `SafeERC20`
- Check for `require(IERC20(token).transfer(...))` patterns that will revert with USDT
- Identify any ERC-20 interaction where the return value is not captured or not validated
- Verify whether the protocol claims to support arbitrary tokens in its documentation

**False Positives**

- When the protocol whitelists only tokens with well-known compliant implementations (WETH, DAI, USDC)
- When the token is protocol-native and its transfer behavior is fully controlled

**Notable Historical Findings**

Reality Cards used bare `IERC20.transfer` calls without checking return values, allowing transfers to silently fail and locking user funds in the contract permanently. NFTX used `transfer` in multiple vault functions, ignoring the boolean return and accepting no-op transfers for tokens that return false on failure. Nouns DAO's fork and quit mechanisms failed when the treasury included non-standard ERC-20 tokens, causing entire fork/quit operations to revert and locking participants out of their proportional treasury share. Holograph's `_payoutToken` used `require(token.transfer(...))`, which reverted for USDT-style tokens even when the transfer succeeded, making payouts non-functional for that token class.

**Remediation Notes**

Replace all direct `IERC20.transfer` and `IERC20.transferFrom` calls with `SafeERC20.safeTransfer` and `SafeERC20.safeTransferFrom`. This handles non-returning tokens, false-returning tokens, and revert-on-failure tokens uniformly. For protocols supporting arbitrary payment tokens, the token whitelist should be the last line of defense, not the only one.

---

### Fee-on-Transfer Token Incompatibility (ref: fv-sol-5)

**Protocol-Specific Preconditions**

- Protocol accepts configurable ERC-20 tokens for deposits, order payments, or staking
- Accounting variables (per-user deposits, `totalDeposits`) are incremented by the nominal transferred amount rather than the actual received amount
- Protocol does not measure balance before and after each incoming transfer

**Detection Heuristics**

- Search for `deposits[user] += amount` or `totalStaked += amount` patterns immediately after `transferFrom(user, address(this), amount)` without a balance snapshot
- Check if protocol documentation states support for all ERC-20 tokens or "arbitrary" payment tokens
- Look for cumulative accounting variables that could drift from actual contract balances over time

**False Positives**

- When the protocol restricts supported tokens to an explicit whitelist that excludes fee-on-transfer tokens
- When balance-before/after snapshots are taken on every incoming transfer

**Notable Historical Findings**

Reality Cards' deposit function credited users with the full `_amount` parameter passed to `transferFrom` regardless of how much the contract actually received, creating a balance deficit that grew with every deposit of a deflationary token. Over time the deficit rendered the contract insolvent for later withdrawers, who could not be paid out because the contract's actual token balance was less than the sum of credited deposits.

**Remediation Notes**

For any protocol that accepts tokens it does not fully control, measure `balanceOf(address(this))` before and after every inbound `transferFrom` and use the difference as the credited amount. This pattern is correct for fee-on-transfer, rebasing, and standard tokens alike.

---

### Unchecked Return Values (ref: fv-sol-6)

**Protocol-Specific Preconditions**

- Contract uses low-level `.call()` for settlement execution or fee forwarding without checking the `bool success` return
- Internal helper functions contain code paths where the return variable is never assigned, defaulting to `false`
- Specific order types (e.g., CONTRACT orders in Seaport) bypass fraction validation applied to all other order types

**Detection Heuristics**

- Search for `target.call(data)` without a follow-up `require(success, ...)` or equivalent branch
- Identify internal functions with non-void return types and audit all code paths for explicit return statements
- Check for `abi.decode(returnData, ...)` without a prior `returnData.length >= 32` guard
- Audit order validation for type-conditional branches that skip numeric invariant checks

**False Positives**

- When failure of the external call is an acceptable, handled outcome (fire-and-forget keeper pattern)
- When default `false` return is the semantically correct answer for the calling code
- When the callee is a known contract that cannot fail under the given conditions

**Notable Historical Findings**

NFTX's `_sendForReceiver` had a code path for non-contract receivers that fell through without an explicit `return true`, causing the function to return `false` even on successful transfers. The calling code interpreted this as a delivery failure and redirected fees to the next receiver in the list, effectively double-paying. Seaport's `AdvancedOrder` validation skipped the `numerator <= denominator` and `denominator > 0` invariants for CONTRACT order types, allowing a denominator of zero to be submitted, which would cause a division-by-zero during fill calculation.

**Remediation Notes**

All code paths in non-void functions must have explicit return statements. Low-level calls must check `success` unconditionally. Order validation invariants must apply to all order types without conditional carve-outs.

### ERC721 and ERC1155 Type Confusion in Dual-Standard Marketplace (ref: pashov-104)

**Protocol-Specific Preconditions**

- The marketplace handles both ERC-721 and ERC-1155 tokens through a shared `buy`, `fill`, or `execute` function that dispatches on a type flag in the order struct
- ERC-721 orders accept a `quantity` field with no requirement that it equals 1
- `price * quantity` payment calculation is performed before type dispatch, allowing a `quantity = 0` order to yield zero required payment
- Settlement proceeds to execute the transfer without validating the payment amount against the actual token type being transferred

**Detection Heuristics**

- Find the shared execution function and check whether ERC-721 order branches include `require(quantity == 1)`
- Verify that `price * quantity` cannot yield zero for an ERC-721 order where `quantity` is caller-controlled
- Check that the type dispatch happens before any payment calculation, not after
- Verify separate code paths exist for ERC-721 and ERC-1155, or that the shared path validates type-specific invariants

**False Positives**

- ERC-721 branches enforce `require(quantity == 1)` unconditionally before any arithmetic
- Payment and transfer logic is fully separated between ERC-721 and ERC-1155 code paths with no shared arithmetic
- `quantity` is not a user-supplied field for ERC-721 orders; it is hardcoded to 1 in the order construction

**Notable Historical Findings**

TreasureDAO suffered a zero-payment NFT theft in 2022 where the shared marketplace fill function accepted ERC-1155-style `quantity` parameters for ERC-721 orders. Setting `quantity = 0` caused the `price * quantity` calculation to yield zero, allowing an attacker to transfer any listed NFT without payment. The fix required adding explicit `require(quantity == 1)` for ERC-721 order types.

**Remediation Notes**

Add `require(quantity == 1)` as the first check in all ERC-721 settlement branches. Prefer fully separate code paths for ERC-721 and ERC-1155 to eliminate cross-type confusion at the cost of some code duplication. Any shared arithmetic over `quantity` must be gated behind a type check.

---

### EIP-2981 Royalty Signaled But Never Enforced (ref: pashov-107)

**Protocol-Specific Preconditions**

- The NFT contract or marketplace implements `royaltyInfo(uint256 tokenId, uint256 salePrice)` and returns true for `supportsInterface(0x2a55205a)` (EIP-2981)
- The marketplace settlement function does not call `royaltyInfo()` or does not route the royalty portion of proceeds to the returned receiver address
- Royalty recipients depend on on-chain enforcement rather than platform-level enforcement for payment

**Detection Heuristics**

- Locate the settlement or transfer execution function. Search for any call to `royaltyInfo(tokenId, salePrice)` and a subsequent payment to the returned receiver address
- Check whether `supportsInterface(0x2a55205a)` returns true; if so, trace whether `royaltyInfo` is ever consumed in settlement
- Verify whether the protocol's documentation accurately represents royalty enforcement as on-chain or platform-dependent
- For marketplace contracts that process arbitrary NFT contracts, confirm the settlement flow queries and respects `royaltyInfo` for any EIP-2981-compliant token

**False Positives**

- Royalties are explicitly set to zero and documented as such; enforcement of zero royalties is a no-op
- The protocol documents that EIP-2981 is implemented for display purposes only and royalty enforcement is handled at the platform layer
- Settlement code calls `royaltyInfo()` and forwards the royalty amount to the royalty receiver before forwarding remaining proceeds to the seller

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

In the settlement function, call `IERC2981(tokenAddress).royaltyInfo(tokenId, salePrice)` when `supportsInterface(0x2a55205a)` returns true, transfer the returned royalty amount to the returned receiver address, and forward only the remaining proceeds to the seller. If royalties are intentionally not enforced on-chain, remove the `royaltyInfo` implementation and return false for `supportsInterface(0x2a55205a)` to avoid misleading on-chain signals.

---
