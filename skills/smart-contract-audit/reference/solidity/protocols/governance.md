# Governance Protocol Security Patterns

> Applies to: DAO governance, on-chain voting, governance token voting, timelocks, proposal execution, treasury management, Compound Governor-style, OpenZeppelin Governor-style

## Protocol Context

Governance protocols derive authority from token-weighted or NFT-weighted voting power, creating a distinct attack surface where vote manipulation translates directly into protocol control. Flash loans allow an attacker to borrow governance tokens for a single block, making snapshot timing the primary defense boundary; if snapshots are taken at the proposal creation block rather than a prior block, same-block attacks collapse that boundary entirely. Delegation chains introduce a second class of risk: the mapping from token holder to effective voter can accumulate stale state, phantom power, and circular dependencies that standard ERC20Votes implementations do not guard against by default.

---

## Bug Classes

### Voting Checkpoint Overwrite in Same Block (ref: fv-sol-5)

**Protocol-Specific Preconditions**

`_writeCheckpoint` updates an existing entry when `block.number` or `block.timestamp` matches the last checkpoint rather than appending. Multiple state-changing operations in one block (mint, stake, transfer, delegate) each call `_writeCheckpoint`, and each overwrites the previous value instead of accumulating the delta. Binary search in `getPastVotes` then returns the final overwritten value, which may be lower than the true aggregate.

**Detection Heuristics**

- Find `_writeCheckpoint` or `_writeCheckpoint`-equivalent implementations. Check the same-block branch: does it assign `newVotes` directly (`cp.votes = newVotes`) or does it add a delta?
- Trace every call site that invokes `_writeCheckpoint` and determine whether two of them can fire in the same transaction (e.g., `_afterTokenTransfer` called twice via `transferFrom` + `delegate`).
- Verify that the storage reference in the same-block branch is a `storage` pointer, not a `memory` copy - a common Solidity footgun where the update does not persist.
- Check `getPastVotes` binary search edge cases: multiple checkpoints sharing the same `fromBlock` value produce ambiguous results.

**False Positives**

- When the overwrite is intentional and the contract never issues more than one checkpoint-modifying operation per block by design.
- When the checkpoint implementation is an unmodified, well-tested upstream library (e.g., OpenZeppelin `ERC20Votes` 4.x+) that uses additive deltas.
- When external ordering guarantees (one-action-per-block limits) make same-block conflicts impossible.

**Notable Historical Findings**

Nouns Builder suffered multiple high-severity findings where `ERC721Votes._writeCheckpoint` created a new entry on every call regardless of block, causing `getPastVotes` binary search to return incorrect historical values; an attacker who minted two NFTs in one block would have their second mint's vote count overwrite rather than add to the first. Golom's `_writeCheckpoint` failed to persist the update to storage when accessing the same-block branch through a `memory`-cached struct, leaving the checkpoint unchanged despite the assignment. FrankenDAO and Telcoin exhibited similar overwrite semantics where `stakedByAt()` reported erroneous values after multiple operations in one block.

**Remediation Notes**

The same-block branch must compute and store the full correct total, not assign `newVotes` blindly. Prefer a pattern where the caller passes `oldVotes` and `newVotes`, allowing the branch to verify internal consistency. Assign through a `storage` pointer, not a locally cached variable. Where possible, use OpenZeppelin's `ERC20Votes` or `ERC721Votes` without modification.

---

### Flash Loan Vote Manipulation (ref: fv-sol-5-c6)

**Protocol-Specific Preconditions**

Governance tokens are available on external lending markets or DEXes. Voting power snapshots are taken at proposal creation block rather than a prior block, or delegation/undelegation can occur atomically in the same transaction as voting. The flash loan mitigation (if any) checks direct token balance but not delegated balance.

**Detection Heuristics**

- Confirm whether `castVote` retrieves power via `getPriorVotes(account, proposalSnapshot)` using a snapshot block strictly before proposal creation, or whether it reads current balance.
- Check if `delegate` + `vote` + `undelegate` can be composed in one transaction. A mitigation that only checks the voter's own balance ignores the case where a flash-loaned amount is deposited, delegated to a proxy contract, and the proxy votes.
- Look for `deposit`/`delegate`/`undelegate`/`withdraw` in governance pool contracts without a cooldown mapping keyed on `msg.sender`.
- Check whether NFT-based `totalPower` is recalculated before the snapshot is written at `createProposal`; a stale denominator yields an artificially low quorum threshold.

**False Positives**

- When the governance token is non-transferable (soulbound) or not available on any lending venue.
- When a mandatory cooldown between delegation and withdrawal (tracked per address per block) prevents same-block unwind.
- When commit-reveal voting schemes break the information asymmetry required for a profitable flash loan attack.

**Notable Historical Findings**

Dexe received a high-severity finding where an attacker bypassed the protocol's direct-vote flash loan check by depositing tokens, delegating to a slave contract, having the slave vote, then undelegating and withdrawing in one transaction - the check applied to the voter account but not the delegatee. A second Dexe finding showed that `ERC721Power::totalPower` was not recalculated before the proposal snapshot, letting an attacker destroy the denominator and manufacture artificially low quorum. PartyDAO allowed any participant to contribute to an ETH crowdfund using a flash loan and then control the resulting party's governance.

**Remediation Notes**

Require that voting power be checkpointed at a block strictly before proposal creation (e.g., `block.number - 1` minimum). Track a `lastDelegationBlock` per address and reject `withdraw` until a cooldown has elapsed. Apply flash loan checks symmetrically to both direct voters and delegatees by locking deposited tokens from withdrawal whenever any proposal voted on by the depositor or their delegatees remains unfinalized.

---

### Delegation State Corruption (ref: fv-sol-5)

**Protocol-Specific Preconditions**

Re-delegation does not remove the old delegatee from the delegations list before inserting the new one, leaving phantom voting power. Delegation to `address(0)` is permitted and triggers `_moveDelegates` toward the zero address, which may revert on mint/burn internally or permanently block token transfers. Self-delegation in a naive implementation adds voting power from the delegator's own balance without subtracting from the prior self-held amount.

**Detection Heuristics**

- In any `delegate(fromTokenId, toTokenId)` function, check that `delegatedTo[fromTokenId]` is read, the old delegatee's power is decremented, and only then the new delegatee is set.
- Search for `delegate(address to)` where `to` is not validated against `address(0)`.
- For self-delegation, trace `_moveDelegateVotes(prevDelegate, to, balanceOf(from))` when `from == to` and `prevDelegate == address(0)` (the implicit default): the call adds `balanceOf(from)` votes to `to` without removing from anywhere, doubling effective power.
- Check NFT-based systems for the case where a burned or withdrawn token remains in a delegatee's list and contributes permanent phantom power.
- Verify that `VoteEscrowDelegation._writeCheckpoint` handles `nCheckpoints == 0` without an underflow on `nCheckpoints - 1`.

**False Positives**

- When delegation is restricted to a trusted set of addresses that are all known and non-zero.
- When the contract explicitly checks `require(to != address(0))` before delegation.
- When self-delegation is implemented via a separate `selfDelegate()` path that routes through a different code branch with correct accounting.

**Notable Historical Findings**

Nouns Builder's `ERC721Votes` had three related high-severity findings: delegation to `address(0)` blocked all transfers and burns for the delegator; self-delegation through `_transferFrom` allowed indefinitely increasing voting power; and explicitly self-delegating via `delegate()` doubled the voting weight by adding balance without removing the implicit prior self-delegation. Golom's `VoteEscrowDelegation` exhibited a related cluster: old delegatees were never removed during re-delegation, NFT withdrawal left stale delegations, and the `_writeCheckpoint` underflowed on the first delegation.

**Remediation Notes**

Always read and clear the previous delegatee before writing the new one. Reject `address(0)` as a delegation target unless the protocol explicitly uses it to mean "undelegate," in which case the handler must decrement without attempting to credit the zero address. Encode the initial state as explicit self-delegation rather than implicit `address(0)` to avoid the dual-path accounting error.

---

### Voting Power Accounting Desync (ref: fv-sol-5)

**Protocol-Specific Preconditions**

A separate `totalCommunityVotingPower` accumulator is maintained alongside per-address balances. Delegation logic only updates the total in specific branches (e.g., when delegating to/from self) and misses the general case of re-delegation between two non-self addresses. Staking records token power at `stake()` time but reads it fresh at `unstake()` time; if a multiplier (e.g., `baseVotes`, `maxStakeBonusTime`) changes between the two calls, the subtraction underflows or over-removes power. The `proposalsCreated` counter is incremented instead of `proposalsPassed` in `queue()`, corrupting the community voting power threshold calculation.

**Detection Heuristics**

- Trace all paths through the `_delegate` function and enumerate every combination of (old delegatee == self, new delegatee == self, old == new). Verify `totalCommunityVotingPower` is adjusted correctly in each branch.
- Find every call to `getTokenVotingPower(tokenId)` and determine whether it is deterministic over time or depends on mutable settings. If mutable, check that `unstake` uses a stored original value.
- Look for counters named `proposalsCreated`, `proposalsPassed`, `proposalsQueued` and verify they are incremented at the correct lifecycle stage.
- Verify `castVote` checks `votingPower > 0` before accepting the vote.

**False Positives**

- When voting power is derived entirely from a single on-chain balance and there is no separate accumulator.
- When stake parameters are immutable after initialization and the power calculation is therefore stable.

**Notable Historical Findings**

FrankenDAO produced four high-severity findings in this class: `totalCommunityVotingPower` was updated incorrectly when a user delegated to a third party (neither self), `unstake` subtracted the current multiplier-adjusted power rather than the original staked power causing underflow, `_unstake` removed votes from `msg.sender` rather than the NFT owner when called by an approved operator, and `queue()` incremented `proposalsCreated` instead of `proposalsPassed`. Alchemix's veCHECKPOINT was found to be completely broken, with voting multiplier rounding errors and unbounded unlock-time extension compounding to allow arbitrary voting power inflation.

**Remediation Notes**

Store the original voting power at stake time in a `mapping(uint256 => uint256)` keyed by token ID and use it exclusively during unstake. In `_delegate`, resolve the four cases (both self, both non-self, self-to-other, other-to-self) explicitly rather than relying on branch fallthrough. Add an invariant test asserting that `sum(tokenVotingPower[a] for all a) == totalCommunityVotingPower` after every state-changing operation.

---

### Quorum and Threshold Manipulation via Live Supply (ref: fv-sol-5-c6)

**Protocol-Specific Preconditions**

`quorum()` or `proposalThreshold()` reads `token.totalSupply()` at call time rather than using a checkpointed historical value. An attacker can mint tokens after proposal creation to inflate the denominator (raising quorum beyond reach) or burn tokens to lower the threshold. NFT-based protocols that compute quorum from `totalPowerInTokens` without recalculating before snapshot allow the denominator to be stale. Protocols that set no minimum voting power requirement for proposal creation allow proposals to be created and passed before any meaningful token distribution has occurred.

**Detection Heuristics**

- Find `quorum()` and `proposalThreshold()` implementations. Check whether they call `totalSupply()` (live) or `getPastTotalSupply(snapshotBlock)` (checkpointed).
- Search for any mint or burn function callable by untrusted actors that executes within the same block as `propose()`.
- In NFT governance, find where `totalPowerInTokens` or equivalent is read for quorum calculation; check whether `recalculateNftPower()` or equivalent is called before the snapshot.
- Check whether `propose()` enforces a non-zero proposer balance requirement and whether that check uses a prior-block snapshot.

**False Positives**

- When minting is permissioned and cannot be triggered by an adversary.
- When the governance token supply is fixed and there is no burn mechanism.
- When a mandatory voting delay ensures the quorum snapshot and the proposal creation block are separated.

**Notable Historical Findings**

Nouns Builder had multiple medium-severity findings related to quorum: burned tokens were not excluded from the denominator, causing quorum to be higher than intended; precision loss in the `quorumThresholdBps` calculation made quorum lower than intended for collections with large supplies; and the protocol allowed a proposal to pass with zero votes in favor during early DAO stages before meaningful distribution. Maia DAO was found to rely on current `bHermes.totalSupply()` for `proposalThresholdAmount`, which could be gamed by minting to block legitimate proposals. Dexe's governance pool used a stale `nftInfo.totalPowerInTokens` as the quorum denominator when `recalculateNftPower()` had not been called prior to snapshot.

**Remediation Notes**

Replace `totalSupply()` calls in quorum and threshold calculations with `getPastTotalSupply(snapshotBlock)`. For NFT-based systems, force recalculation of aggregate NFT power immediately before writing the proposal snapshot. Add a protocol-minimum `proposalThreshold` that ensures no proposals can be submitted before a baseline token distribution has occurred.

---

### Proposal Threshold Bypass via Signature Aggregation (ref: fv-sol-4)

**Protocol-Specific Preconditions**

`proposeBySigs()` accepts an array of signers and sums their voting power, but does not verify that the aggregate sum meets the proposal threshold at the snapshot block. Alternatively, each signer is validated individually (ensuring their signature is valid) but no combined-power check is performed. This allows many low-balance accounts to collectively submit proposals that no single account would be authorized to create.

**Detection Heuristics**

- Find `proposeBySigs` or equivalent signature-based proposal submission functions. Check whether a `require(totalVotingPower >= proposalThreshold())` or equivalent guard exists after the loop over signers.
- Verify that the threshold is read at the proposal's snapshot block, not at the time of transaction execution.
- Check if any signer can unilaterally cancel a pending proposal - a high-severity variant where the `cancel()` function checks only that the caller is among the original signers.

**False Positives**

- When `proposeBySigs` is a governance-only function callable only by a trusted multisig.
- When there is an additional on-chain veto or guardian that prevents malicious proposals from executing.

**Notable Historical Findings**

Nouns DAO received a medium-severity finding where `proposeBySigs()` did not verify that combined voting power met the proposal threshold, enabling low-balance accounts to collectively spam proposals. A separate high-severity finding in the same audit showed that any single signer from the original set could call `cancel()` to grief any pending or active proposal, regardless of whether the other signers agreed. Alchemix received a medium-severity finding where a malicious proposer could front-run and inflate `proposalThreshold` to block legitimate proposals from being submitted.

**Remediation Notes**

After iterating over signers and accumulating `totalVotingPower`, add `require(totalVotingPower >= proposalThreshold(), "below threshold")` using `getPastVotes` at the proposal snapshot block. Restrict `cancel()` to require either the original proposer or a majority of signers, not any single signer.

---

### Delegation Griefing via MAX_DELEGATES DoS (ref: fv-sol-9)

**Protocol-Specific Preconditions**

The governance contract enforces a maximum number of token IDs delegated to any single address (`MAX_DELEGATES`, commonly 1024). There is no minimum token balance required to perform a delegation. An attacker creates many dust positions (1 wei each) and delegates all of them to a target address, filling the limit and preventing any legitimate user from delegating to the target. The target cannot reset the limit by self-delegating.

**Detection Heuristics**

- Find the `MAX_DELEGATES` constant and the `delegate()` function. Check whether a minimum balance (`MIN_DELEGATION_BALANCE`) is enforced.
- Check whether the delegation limit check uses `ownerToTokenCount[owner]` or `balanceOf(owner)` - count-based limits are more easily exhausted with dust than balance-based limits.
- Verify that `_moveAllDelegates` or equivalent does not allow an attacker to atomically move hundreds of dust positions to a victim in one transaction.

**False Positives**

- When the cost of acquiring 1024 distinct positions (gas + token cost) is prohibitive relative to the griefing value.
- When the victim can self-delegate to clear the delegate list.
- When delegation is restricted to accounts that hold above a meaningful minimum balance.

**Notable Historical Findings**

Alchemix received multiple related medium-severity findings: `DOS attack by delegating tokens at MAX_DELEGATES = 1024` appeared in both the VotingEscrow and standard token contexts; a griefing variant showed any account could fill a victim's delegate limit at 100x lower cost than the victim's transfer cost; and a separate finding showed the same pattern allowed arbitrary asset freezing. Velodrome Finance received the same finding category, with `MAX_DELEGATES = 1024` fillable through dust delegation with no minimum balance guard.

**Remediation Notes**

Enforce a `MIN_DELEGATION_BALANCE` check in `delegate()` that requires the delegating account to hold above a meaningful threshold. Alternatively, limit the number of distinct delegations per source account (not just per target) so a single attacker address cannot farm positions across many wallets. Consider using a balance-weighted cap rather than a count-based cap.

---

### Unbounded Lock Duration Inflating Voting Power (ref: fv-sol-5)

**Protocol-Specific Preconditions**

Voting power is calculated as `baseVotes + (unlockTime - block.timestamp) * MULTIPLIER`. No upper bound is enforced on `_unlockTime`. An attacker passes `type(uint256).max` as `_unlockTime`, producing an astronomically large `stakedTimeBonus` that overflows or dominates all other voting power in the system, enabling unilateral governance control.

**Detection Heuristics**

- Find staking or lock functions that accept a `_unlockTime` or `lockDuration` parameter. Check for `require(_unlockTime <= block.timestamp + MAX_LOCK_DURATION)` or equivalent.
- Check whether `stakingSettings.maxStakeBonusTime` is actually enforced in the staking function or is merely a stored value that is never validated against the input.
- Trace the arithmetic: does `(unlockTime - block.timestamp) * MULTIPLIER` use SafeMath or checked arithmetic? An unchecked multiplication with `type(uint256).max` will overflow silently in Solidity <0.8.

**False Positives**

- When the lock duration is derived from a fixed enum (e.g., 1 week / 1 month / 1 year) and the user cannot supply an arbitrary value.
- When overflow protection (Solidity 0.8+ or SafeMath) causes the transaction to revert before the inflated power is recorded.

**Notable Historical Findings**

FrankenDAO's `_stakeToken` accepted an arbitrary `_unlockTime` and multiplied the uncapped duration by `STAKED_TIME_MULTIPLIER`, allowing an attacker to set `_unlockTime = type(uint256).max` and acquire a voting bonus large enough to pass any proposal unilaterally. The same pattern appeared across both liquid-staking and yield categories, in every case because `stakingSettings.maxStakeBonusTime` was stored but the staking function never compared the user input against it.

**Remediation Notes**

Add `require(_unlockTime <= block.timestamp + stakingSettings.maxStakeBonusTime, "exceeds max lock")` as the first check in the staking function. Store the computed voting power at stake time and use the stored value at unstake time to prevent desync if the max lock duration is later reduced.

---

### Governance Parameter Manipulation and Veto Loss (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**

Governance parameters (quorum thresholds, fork periods, veto rights, `forkThresholdBPS`) are settable by a privileged role or by governance itself without a timelock. A malicious or compromised owner can set parameters to values that trap token holders: setting `forkPeriod` to a near-zero value prevents exit, setting `forkThresholdBPS` to 100% prevents reaching the fork threshold. A vetoer address that is renounced or set to zero eliminates the last line of defense against a 51% attack.

**Detection Heuristics**

- Find all governance parameter setters. Check whether they are gated behind a timelock of meaningful length (>= the voting period).
- Identify whether a vetoer, guardian, or emergency pause role exists. Verify it cannot be unilaterally renounced by a single key without a governance vote.
- Check `cancel()` logic: can proposals be cancelled by accounts other than the original proposer without a majority of voting power backing the cancellation?
- Look for missing timelock checks on `diamondCut` or upgrade functions callable directly by a governor without delay.

**False Positives**

- When all parameter changes require a full governance proposal with a standard timelock.
- When the guardian role requires a multisig with a distributed key set.
- When the protocol is not yet live and parameters are being configured during initialization.

**Notable Historical Findings**

Nouns DAO received a cluster of medium-severity findings where a malicious DAO could manipulate `forkThresholdBPS`, set `forkPeriod` to an extremely low value trapping token holders, mint arbitrary fork DAO tokens, and update a proposal's content after inattentive voters had already cast their votes. Nouns Builder and Velodrome Finance both received findings that loss of the vetoer role opens a 51% attack path: once a sufficiently large token holder acquires a majority, no on-chain mechanism prevents proposal execution in the absence of a veto. ZkSync received a medium finding where the governor could immediately execute diamond upgrades without any timelock.

**Remediation Notes**

All governance parameter changes should be routed through a timelock whose duration is at minimum equal to the voting period, preventing the parameter from taking effect before any ongoing proposal concludes. The vetoer or guardian role should require multi-party authorization to transfer or revoke. Proposal content should be hashed and committed at creation time; any update should invalidate existing votes.

### Governance Flash-Loan Proxy Upgrade Hijack (ref: pashov-90)

**Protocol-Specific Preconditions**

Proxy contract upgrades are authorized by governance votes that read vote weight from the current block (`balanceOf` or `getPastVotes(account, block.number)`) rather than a prior checkpoint. No voting delay forces a waiting period between proposal creation and voting. No timelock delays execution after a vote passes. An attacker can flash-borrow sufficient governance tokens, create a proposal, vote, and execute an upgrade to a malicious implementation within a single transaction.

**Detection Heuristics**

- Find the vote weight lookup in `castVote` or equivalent; verify it uses `getPastVotes(account, block.number - 1)` or a snapshot block strictly before the proposal's creation block, not the current block.
- Check whether a `votingDelay` parameter is non-zero and enforced, preventing a proposal from being voted on in the same block it was created.
- Verify that a timelock of meaningful duration (24 hours minimum) sits between vote execution authorization and the actual upgrade call.
- Check whether governance token staking has a lock-up period that prevents flash loan acquisition.

**False Positives**

- Vote weight is read from `getPastVotes(account, block.number - 1)` with a voting delay enforced in addition.
- A timelock of at least 24 hours is interposed between vote finalization and execution.
- A quorum threshold is set high enough that flash-loan capital cannot reach it without exhausting the available lending market for the governance token.
- Governance tokens require staking with a lock period, blocking flash loan-based participation.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Use `getPastVotes(account, block.number - 1)` as the minimum snapshot offset and enforce a non-zero `votingDelay` so that snapshot and voting blocks are strictly separated. Require a timelock of at least 24 to 72 hours between vote execution authorization and any upgrade or parameter-change execution. For protocols whose governance tokens are available on lending markets, consider requiring staked governance tokens with a lock period for voting power.

---

### Flash Loan Vote Manipulation for Arbitrary Proposals (ref: pashov-131)

**Protocol-Specific Preconditions**

Voting power is read from `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` at the time of the vote, allowing a flash loan of governance tokens to provide voting power within the same transaction. There is no minimum holding period between token acquisition and voting, and no timelock between vote finalization and execution. An attacker can borrow tokens, vote on or pass a proposal, and repay the loan within one atomic transaction.

**Detection Heuristics**

- Check the vote power source in `castVote` or `_countVote`; any read of `balanceOf` or `getPastVotes(account, block.number)` is exploitable via flash loan.
- Verify whether a cooldown or lock period prevents a newly acquired token balance from being used for voting until at least the next block.
- Check whether a meaningful timelock separates vote finalization from execution.
- Simulate the flash loan path: borrow tokens, delegate if necessary, vote, and verify whether the proposal is executable within the same transaction.

**False Positives**

- `getPastVotes(account, block.number - 1)` is used with a snapshot taken strictly before the proposal's creation block.
- A mandatory timelock sits between a passed vote and execution, making intra-transaction execution impossible.
- The governance token is non-transferable or unavailable on any lending venue that would supply flash loan liquidity.

**Notable Historical Findings**

No specific historical incidents cited in source.

**Remediation Notes**

Replace any `balanceOf` or current-block `getPastVotes` call with `getPastVotes(account, proposalSnapshot)` where `proposalSnapshot` is set to a block strictly before proposal creation. Enforce a non-zero `votingDelay` in the governor contract. Add a timelock between vote finalization and execution to ensure that governance decisions cannot be atomically proposed, voted, and executed within a single transaction.

---
