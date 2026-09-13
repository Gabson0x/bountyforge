# RWA Lending Protocol Security Patterns

> Applies to: lending protocols backed by real world assets, undercollateralized RWA loans, RWA credit markets, Maple-style, TrueFi-style, Goldfinch-style, institutional on-chain credit

## Protocol Context

RWA lending protocols extend on-chain credit backed by off-chain collateral, typically to institutional borrowers under legal agreements that the smart contract enforces through credit lines, pools, and fixed repayment schedules. Unlike overcollateralized DeFi lending, these protocols operate with undercollateralization by design and rely on credit assessment, legal recourse, and pool diversification rather than liquidation bots to manage default risk. The smart contract layer is responsible for correctly tracking credit principal and accrued interest, enforcing withdrawal queue ordering, and maintaining accurate accounting across pool participants who may have different seniority.

The attack surface is concentrated in credit queue data structures that maintain ordered state across multiple borrows and repayments, payment routing logic that must correctly distinguish interest from principal, and push-payment patterns in credit close flows where a malicious lender contract can permanently block settlement. Unbounded iteration over credit arrays, rounding errors in time-weighted debt decay, and ETH/ERC-20 handling asymmetries in repayment functions are the most common sources of high-severity findings in audits of this protocol class.

## Bug Classes

---

### Credit Line Queue Corruption (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol manages active credit positions using an ordered array where index 0 carries special meaning (first to be repaid, basis for liquidation eligibility, anchor for insolvency checks). Operations that remove or close entries can produce zero-value gaps in the array. Sorting logic that re-inserts positions skips gaps, leaving them in place indefinitely. Modifiers guarding liquidation and insolvency declaration check `credits[ids[0]].principal == 0` to determine whether borrowing is active, producing a false negative when gaps exist and position 0 is a zero stub.

**Detection Heuristics**
Identify all functions that modify the credit queue array: close, repay, borrow, and any administrative override. Verify that each removal path leaves no zero-value gaps and does not decrement the count for a non-existent entry. Confirm that the `whileBorrowing` modifier (or equivalent) checks for any live principal across the full array, not only at index 0. Trace what happens when `close()` is called with an ID that was never created: does the mapping return a zero-struct that passes the caller check, and does the subsequent `_close` decrement an already-zero count?

**False Positives**
Protocols that use a linked list rather than an array, where index-0 assumptions do not apply. Protocols where every entry point validates existence before modifying the queue, making the zero-struct bypass path unreachable. Arrays maintained as a densely packed set where removals always shift elements left.

**Notable Historical Findings**
In Debt DAO's Line of Credit, a borrower could call `close()` with a non-existent credit ID because the function fetched from the mapping without an existence check; the zero-struct's zero lender address bypassed the caller guard (the borrower always matched), and the subsequent `_close` decremented the `count` to an incorrect value. A separate finding showed that calling `declareInsolvent()` after repaying the first credit position caused a revert because the queue sorting left a zero-value gap at index 0, making the `whileBorrowing` modifier falsely conclude no active debt existed and block the insolvency path.

**Remediation Notes**
Add an explicit existence check (e.g., `credit.lender != address(0)`) as the first operation in any function that reads from the credit mapping. Adjust the `whileBorrowing` modifier to scan the full array for non-zero principal rather than relying on a single index. Ensure the queue sorting function fills gaps rather than skipping them.

---

### ETH Handling and Refund Errors (ref: fv-sol-6)

**Protocol-Specific Preconditions**
Contract has payable functions that accept both ETH and ERC-20 tokens using the same function signature. The ETH receipt path uses a less-than comparison (`msg.value < amount`) rather than strict equality, allowing excess ETH to be silently retained. When the ERC-20 path is invoked, any ETH accidentally included with the call is locked without refund. Outgoing ETH payments use `payable.transfer()`, which fails for smart contract recipients whose `receive()` function consumes more than 2,300 gas.

**Detection Heuristics**
Search for payable functions that branch on a token-address sentinel (e.g., `address(0)` or `Denominations.ETH`) to distinguish ETH from ERC-20. On the ETH branch, verify the comparison is `!= amount` rather than `< amount`. On the ERC-20 branch, verify a revert is triggered when `msg.value > 0`. For outgoing ETH transfers, confirm `call{value:}` is used instead of `.transfer()`. Check whether the `sender` parameter in a shared `receiveTokenOrETH` helper is validated against `msg.sender` when ETH is the token, to prevent spoofed-sender crediting.

**False Positives**
Contracts that intentionally accept ETH donations above the required amount and credit the excess to the sender in internal accounting. Contracts with a dedicated `rescueETH` admin function that recovers any locked ETH.

**Notable Historical Findings**
In Debt DAO, the `receiveTokenOrETH` function used `msg.value < amount` on the ETH path; any excess ETH was accepted and permanently locked in the contract. The same function did not reject ETH on the ERC-20 path, so a caller who mistakenly included ETH with a token transfer lost those funds silently. Outgoing ETH sends in `sendOutTokenOrETH` used `payable(receiver).transfer(amount)`, which failed for any receiver that was a smart contract with a non-trivial receive function.

**Remediation Notes**
Use strict equality (`msg.value != amount`) on the ETH receive path. Revert immediately when `msg.value > 0` on the ERC-20 path. Replace all `payable.transfer()` ETH sends with `call{value:}` and check the return value. Validate `msg.sender == sender` when the payment is ETH to prevent sender spoofing through the shared helper.

---

### Frontrunning Unprotected State Transitions (ref: fv-sol-5)

**Protocol-Specific Preconditions**
A function performs a critical state transition against an implicit target read from contract state rather than an explicit identifier supplied by the caller. The target can change between the time the user signs and submits the transaction and the time it is mined. Governance vote functions reference `activeProposal` from state, allowing a proposal swap to redirect votes to an unintended proposal. NFT claim functions do not mark the ticket as claimed before the transfer, enabling owner front-running. Lender-controlled external call data (e.g., swap calldata) is passed through unchecked, allowing value redirection.

**Detection Heuristics**
Identify functions where the subject of the operation is read from a state variable rather than supplied as a parameter. Check governance vote paths for the presence of an explicit proposal ID parameter and a corresponding equality check against the active proposal. Audit claim functions for a mark-before-transfer pattern. Search for functions that accept arbitrary external call data from a non-borrower caller and execute it against third-party contracts.

**False Positives**
Functions callable only by trusted roles where mempool observation is not relevant. Atomic state transitions that cannot be reordered within a single block. Protocols using private mempools or commit-reveal schemes that make front-running economically infeasible.

**Notable Historical Findings**
In Olympus DAO, the `vote()` function read `activeProposal.proposalId` from state without requiring the caller to specify which proposal they intended to vote on; if a new proposal was activated between submission and mining, the user's votes were silently redirected. In Debt DAO, a lender could supply malicious `zeroExTradeData` calldata to `claimAndRepay`, redirecting swap proceeds away from the borrower's collateral repayment. In Wenwin, an NFT ticket owner could front-run a buyer's purchase transaction by calling `claimWinningTickets` first, collecting the reward before the transfer settled.

**Remediation Notes**
Require explicit target identifiers as function parameters and validate them against current state (e.g., `require(proposalId == activeProposal.proposalId)`). Restrict caller-controlled external call data to the borrower or a trusted role. Mark claims as consumed before any external transfer or payment using checks-effects-interactions.

---

### Funds Locked in Edge-Case States (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Reward distribution sends tokens to a staking or recipient contract before any stakers exist, with no mechanism to account for or recover those tokens. A prediction market or binary outcome contract reaches a state where all participants chose the same direction, making `totalWinningAmount == 0` and blocking all claims. A credit line close path sends funds directly to the lender using a push pattern; a lender contract that reverts on token receipt can permanently block the close operation, trapping borrower funds.

**Detection Heuristics**
Identify all reward distribution or prize-sending paths and check behavior when the eligible recipient count or total winning stake is zero. Look for push-payment patterns in credit close and repayment flows where the recipient is a potentially hostile or failing contract. Verify that every protocol state that receives funds has a corresponding exit path that does not depend on all participants behaving correctly.

**False Positives**
Protocols that guarantee at least one staker through an initialization deposit or minimum stake requirement enforced at launch. Protocols with an admin emergency withdrawal function that can bypass normal accounting invariants. Stuck amounts negligible relative to total protocol value.

**Notable Historical Findings**
In Wenwin, `claimRewards` transferred staking rewards to the `stakingRewardRecipient` contract even when it had zero stakers, permanently locking those tokens because the staking contract's reward accounting produced no claimable amounts. In a prediction market protocol, when all users selected the same direction, `totalWinningAmount` evaluated to zero and every user's claim reverted, locking the entire round's prize pool. In Debt DAO, a lender contract that reverted on token receipt (via a hook or malicious `receive`) could block `_close` indefinitely because the send was mandatory and had no fallback.

**Remediation Notes**
Check for zero-recipient or zero-winner edge cases in every distribution function and route unclaimed funds to a treasury address or preserve them for a subsequent period. Replace push-payment patterns in credit close flows with pull-payment accounting (credit internal balances, allow lenders to withdraw separately). For prediction markets, implement a no-winner fallback that returns funds to depositors or a protocol reserve.

---

### Irrevocable Whitelist or Approval (ref: fv-sol-4)

**Protocol-Specific Preconditions**
Protocol maintains a whitelist or approval mapping for auctioneers, tellers, or revenue contracts that can invoke privileged callbacks or receive funds. An `add` function exists but no corresponding `remove` or `revoke` function. A whitelisted entity that becomes compromised retains all its permissions permanently.

**Detection Heuristics**
Enumerate all mappings and arrays used as access control lists. Confirm that every `add`/`register`/`whitelist` function has a symmetric `remove`/`deregister`/`revoke` counterpart. Assess the blast radius of a whitelisted entity being compromised: can it transfer funds, redirect callbacks, or drain the contract? Check whether the only available mitigation is a full contract pause, which would affect all users.

**False Positives**
Whitelisted entities that are immutable, non-upgradeable contracts incapable of being compromised. Protocols with a pause mechanism that effectively neutralizes a compromised entity without requiring removal. Permissionless designs where whitelist removal is intentionally omitted to prevent censorship.

**Notable Historical Findings**
In Bond Protocol, the `BondAggregator.registerAuctioneer` function set `_whitelist[address(auctioneer_)] = true` with no deregistration function anywhere in the codebase; a compromised auctioneer would permanently retain the ability to operate markets and receive proceeds. The same protocol's teller approval mapping (`approvedMarkets[teller_][id_] = true`) similarly lacked any revocation function, leaving any compromised teller with irrevocable market-level permissions.

**Remediation Notes**
Implement a symmetric removal function for every addition function that modifies an access control mapping. Ensure the removal function is callable by the same authorized role as the addition function and emits an event for off-chain monitoring. Document the expected response procedure for a compromised whitelisted entity.

---

### Missing Existence Validation on State Operations (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol stores credits, markets, or revenue contracts in mappings where non-existent keys return zero-value structs. Operations that modify or query these entities do not verify the entity was previously created. The default zero-value struct inadvertently satisfies validation conditions (e.g., `claimFunction == bytes4(0)` is treated as a valid push-payment mode rather than an unregistered contract). Count or index decrements execute successfully on non-existent entities, corrupting accounting.

**Detection Heuristics**
Identify every mapping lookup where the key is derived from user input or an unvalidated external parameter. Check that the retrieved struct is validated for existence before use - the canonical check is a non-zero address field (`credit.lender != address(0)`). Trace count and array modifications: do they proceed on a zero-struct without reverting? Verify whether zero-value fields in the struct could activate code paths that would only be valid for registered entities.

**False Positives**
Mappings iterated exclusively from a known-valid in-memory array, guaranteeing all accessed keys were previously inserted. Zero-struct returns that cause the function to revert before any state change through a downstream check. Code paths behind access control that prevent untrusted callers from triggering the missing validation.

**Notable Historical Findings**
In Debt DAO, calling `close()` with a never-registered credit ID fetched a zero-struct that passed the caller check (borrower always matched the zero-lender condition) and then decremented `count`, corrupting the queue state. A separate finding showed that passing an unregistered revenue contract to `claimRevenue` was treated as a valid push-payment configuration because `claimFunction == bytes4(0)` matched the push-payment sentinel; the zero `ownerSplit` field then sent 100% of any existing contract balance to the protocol treasury rather than the owner.

**Remediation Notes**
Add an explicit existence guard as the first statement in any function that reads from a mapping keyed by user input. Use a non-zero address field (lender, owner, creator) as the existence sentinel rather than relying on downstream logic to catch zero values. Document the canonical sentinel field for each mapping to enforce consistent validation across callers.

---

### Reentrancy via Token Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**
Contract transfers tokens to a user-controlled address (lender, credit recipient) before deleting the associated state record. The transferred token supports transfer callbacks (ERC-777 `tokensReceived`, ERC-1155 `onERC1155Received`, or ETH `receive`). No `nonReentrant` guard is applied. The re-entrant call finds the credit record still intact, allowing it to extract the deposit or principal a second time before the delete executes. Read-only reentrancy via Curve's `get_virtual_price` allows external protocols that read the LP token price to receive a stale value during a `remove_liquidity` callback.

**Detection Heuristics**
Identify functions that send tokens or ETH to user-controlled addresses. Check whether the delete or balance-update of the corresponding state record occurs before or after the transfer. Search for absence of `nonReentrant` on credit close, repayment, and withdrawal functions. For Curve LP token pricing, verify that a reentrancy lock is triggered before reading `get_virtual_price` to prevent read-only reentrancy.

**False Positives**
Token whitelist that explicitly excludes all tokens with transfer hooks and is enforced at protocol level with no upgrade path. State changes that already occur before the external transfer, satisfying the checks-effects-interactions pattern throughout. Reentrancy guards present on all public entry points.

**Notable Historical Findings**
In Debt DAO, `_close` sent deposit plus accrued interest to the lender before deleting the credit record and decrementing the count; an ERC-777 lender could re-enter `_close` during the callback, receiving the payment twice while the credit record remained live. A Sentiment Update #2 finding demonstrated read-only reentrancy against the wstETH-ETH Curve pool: during a `remove_liquidity` call, `get_virtual_price` returned a stale pre-withdrawal value, allowing an attacker to borrow against an inflated LP token price.

**Remediation Notes**
Follow checks-effects-interactions strictly: delete the credit record and update all counters and status flags before making any external transfer. Apply `nonReentrant` to all public and external functions that transfer value. For Curve LP token pricing, trigger the pool's reentrancy lock (e.g., a zero-amount `remove_liquidity` call) before reading `get_virtual_price`.

---

### Rounding Direction Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
Protocol performs division in price, debt decay, or reward calculations where the rounding direction has financial consequences for one party. The protocol's specification or whitepaper explicitly states the required rounding direction. The implementation uses a standard `mulDiv` (round-down) function where a round-up would be correct, or applies the same rounding direction inconsistently across related calculations (e.g., public market price vs. internal market price).

**Detection Heuristics**
Identify all `mulDiv`, `div`, and integer division operations in price, reward, and time-decay calculations. Determine who benefits from rounding in each direction (protocol, maker, taker, staker). Compare the implementation's rounding direction to any specification or whitepaper. Look for inconsistency where the same formula rounds differently depending on which code path is executed. Check for unsafe casts that implicitly truncate precision (e.g., `uint256` to `uint16` for ticket prizes).

**False Positives**
Rounding errors bounded to sub-wei amounts per operation where cumulative impact is negligible. Calculations where both the specification and implementation intentionally round in the protocol's favor for safety margins. Division results used in contexts where rounding direction has no observable financial effect.

**Notable Historical Findings**
In Bond Protocol, `_currentMarketPrice` used `mulDiv` (round-down) where the specification required rounding up to protect sellers from receiving less than the quoted price; the resulting underpricing was systematic and compounded across all market activity. The same protocol's debt decay increment used round-down when the specification required round-up, causing debt to decay faster than intended and reducing the protocol's solvency buffer.

**Remediation Notes**
Implement a `mulDivUp` utility (rounding up) alongside `mulDiv` and apply the correct variant per the specification. Audit all price and debt calculations against any published specification for explicit rounding requirements. Treat rounding direction as a protocol invariant to be verified in unit tests with boundary inputs.

---

### Stale or Manipulable Price Data (ref: fv-sol-10)

**Protocol-Specific Preconditions**
Protocol uses Chainlink oracle feeds with inconsistent staleness thresholds: one feed allows three times the observation frequency before reverting while another allows only one, making the effective combined freshness guarantee weaker than either threshold alone. Curve `get_virtual_price` is called without a reentrancy lock, making it vulnerable to read-only reentrancy during `remove_liquidity` callbacks. A keeper-driven heartbeat system keeps prices active, but no staleness check is performed at the point of swap or liquidation; if the keeper stops, the protocol continues using arbitrarily old prices.

**Detection Heuristics**
Enumerate all Chainlink `latestRoundData` calls and check that each includes `updatedAt < block.timestamp - threshold` validation. Compare staleness thresholds across all feeds used in the same calculation - they should be equivalent or the weaker threshold should govern. Look for `get_virtual_price` calls not preceded by a reentrancy guard. Identify heartbeat-dependent protocols and check whether the swap or liquidation path validates that the last heartbeat timestamp is within an acceptable window.

**False Positives**
Staleness windows that differ intentionally because oracle update frequencies genuinely differ and the threshold is calibrated to each feed's actual heartbeat. TWAP oracles with windows long enough to make momentary manipulation economically infeasible. Price feeds used only for non-critical display or informational purposes where staleness has no financial consequence.

**Notable Historical Findings**
In Olympus DAO, the OHM-ETH feed's staleness threshold was three times the observation frequency while the reserve-ETH feed's threshold was one times; an attacker could profit from the asymmetry by timing operations to the window where the reserve feed was stale but still accepted. The same protocol's RBS system kept swap walls active even when the heartbeat had not been called, meaning users and bots could execute swaps against arbitrarily old prices. A Sentiment Update #2 finding showed that Curve's `get_virtual_price` could be manipulated via a re-entrant `remove_liquidity` call, artificially inflating the LP token price used as collateral.

**Remediation Notes**
Apply a uniform staleness threshold to all feeds combined in the same calculation, calibrated to the feed with the slowest update frequency. Add a reentrancy guard before reading `get_virtual_price` from any Curve pool. Require that heartbeat-dependent pricing systems verify heartbeat freshness at the point of each swap or liquidation rather than relying on an external keeper to always be online.

---

### Timestamp and Expiry Rounding Bypass (ref: fv-sol-5)

**Protocol-Specific Preconditions**
Protocol generates token or bond identifiers by hashing (underlying, expiry) where expiry is rounded to the nearest day internally in one code path but accepted as-is in another. A user who calls `deploy()` with a non-rounded expiry creates a token with a different ID than the one produced by `_handlePayout()`, breaking the token's fungibility and redemption path. Separately, boundary timestamp comparisons use strict inequalities (`<` or `>`) where inclusive comparisons (`<=` or `>=`) are required, allowing two mutually exclusive operations (e.g., execute draw and buy ticket) to occur atomically in the same block.

**Detection Heuristics**
Find all paths that create or reference time-indexed tokens and verify that every path applies the same rounding function to the expiry. Compare `deploy()` or public creation functions against internal mint functions for rounding consistency. For time-gated operations, check every boundary comparison for off-by-one errors: `< deadline` vs. `<= deadline` and `> deadline` vs. `>= deadline`. Identify pairs of operations that should be mutually exclusive at epoch boundaries and verify they cannot both execute at the same `block.timestamp`.

**False Positives**
Off-by-one boundary conditions with no practical impact because the two operations cannot be submitted atomically (e.g., they require distinct signers with no time coordination). Rounding differences that are cosmetic and do not affect token ID generation or financial calculations. Cooldown periods that prevent the boundary condition from being exploitable even if it is reachable.

**Notable Historical Findings**
In Bond Protocol's Fixed Term Teller, `deploy()` did not round the expiry to the nearest day while `_handlePayout()` did; tokens created through `deploy()` with a mid-day expiry had different IDs than tokens minted through normal purchase flows, making them non-redeemable through the standard redemption path. A separate finding showed that `deploy()` accepted expiries in the past without reverting, allowing creation of immediately redeemable tokens at any price. In Wenwin, the `executeDraw` boundary used `<` instead of `<=`, allowing it to execute at the exact same block timestamp that `beforeTicketRegistrationDeadline` still admitted ticket purchases, creating a race condition where a user could buy a ticket and immediately claim the jackpot in the same block.

**Remediation Notes**
Apply expiry rounding consistently in every function that generates time-indexed identifiers. Validate that expiries are strictly in the future after rounding is applied. Use inclusive boundary comparisons at epoch and deadline boundaries to prevent same-block co-execution of mutually exclusive operations.

---

### Unbounded Loop Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
Protocol maintains a market counter, prediction array, or position list that grows unboundedly over the protocol's lifetime. A function iterates over the full collection from index 0 to the current counter without a pagination mechanism. The function is on the critical path for claims, withdrawals, or liquidations that must succeed for users to recover funds. Gas cost grows linearly with the collection size and will eventually exceed the block gas limit.

**Detection Heuristics**
Identify all loops where the iteration bound is a state variable that can grow monotonically without a ceiling enforced at insertion time. Check whether the iterated function is a view function (DoS is limited to off-chain reads) or a state-changing function on the critical path (DoS blocks user funds). Estimate gas cost at realistic scale: a collection of 10,000 entries with a per-element cost of 5,000 gas exceeds 50M gas, above most chain block limits. Check for double iteration patterns (collect count, then fill array) that double the gas cost.

**False Positives**
Arrays with a hard-coded maximum size enforced at insertion, where the gas cost at the cap fits within the block gas limit. View-only functions where DoS only affects off-chain tooling and does not block on-chain fund recovery. Protocols with a finite, well-bounded lifetime where the collection cannot grow beyond safe limits.

**Notable Historical Findings**
In Bond Protocol, `BondAggregator.liveMarketsBy` iterated over all markets ever created twice (once to count, once to fill the result array); as market count grew, the function would revert on-chain due to block gas limits. The same protocol's `findMarketFor` function would revert in certain conditions due to unbounded market array traversal. In a prediction market protocol, `claimReward` iterated the full predictions array for a given round; once enough predictions accumulated in a single round, all claim transactions for that round failed permanently.

**Remediation Notes**
Add `start` and `stop` index parameters to any function that iterates over a growing collection, and enforce `stop <= collectionSize` at call time. Prefer off-chain indexing for read-heavy queries, exposing only paginated on-chain access. Cap insertions per round or market at a size provably safe at the block gas limit. For claim paths that could block fund access, redesign to allow per-user O(1) claims rather than full-array iteration.

---

### Unsafe Arithmetic in Unchecked Blocks (ref: fv-sol-3)

**Protocol-Specific Preconditions**
Contract wraps repayment or debt accounting logic in a Solidity `unchecked` block for gas savings. Within the block, a subtraction occurs where the right-hand operand (payment amount, principal payment) could exceed the left-hand operand (accrued interest, recorded principal). No explicit bounds check precedes the subtraction. The resulting underflow silently wraps to a very large value that is stored in the credit's principal or debt fields, converting a normal repayment into an apparent massive debt that triggers immediate liquidation.

**Detection Heuristics**
Search for all `unchecked { }` blocks in the codebase. Within each, identify every subtraction and verify that a preceding `require` or conditional prevents the right operand from exceeding the left. Trace the source of each operand: user-supplied amounts and values derived from external calls are highest risk. Assess the downstream impact of an underflowed value being stored in debt, balance, or prize accounting.

**False Positives**
`unchecked` blocks used exclusively for loop counter increments (`++i`) where overflow is impossible in practice. Subtractions guarded by a prior conditional that makes the subtraction safe (e.g., `if (amount <= credit.interestAccrued) { unchecked { credit.interestAccrued -= amount; } }`). Arithmetic proved safe by invariants that are enforced at every prior entry point.

**Notable Historical Findings**
In Debt DAO, the `repay` function's `unchecked` block subtracted `principalPayment` from `credit.principal` without verifying that `principalPayment <= credit.principal`; a borrower who overpaid (amount exceeding total owed) produced an underflow that set `credit.principal` to a value near `type(uint256).max`, placing the position immediately into liquidation. In Wenwin, a `uint256` to `uint16` unsafe cast in lottery prize calculations silently truncated large prize values, causing winners to receive far less than their correct payout.

**Remediation Notes**
Add an explicit upper-bound check before every subtraction within an `unchecked` block, even when the operands appear logically constrained. Use OpenZeppelin `SafeCast` for all explicit downcasts. Reserve `unchecked` for arithmetic that has been formally proved safe - document the invariant that makes each `unchecked` operation safe in a code comment adjacent to the block.
