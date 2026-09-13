# Token Launchpad Security Patterns

> Applies to: token launchpads, IDO platforms, token sales, fair launches, vesting contracts, token distribution protocols, Fjord-style, Camelot-style

## Protocol Context

Token launchpad contracts manage the full lifecycle of token distribution: from whitelist verification and sale mechanics (Dutch auctions, fixed-price, LBPs) through vesting schedules and governance bootstrapping. They concentrate both ETH and newly issued tokens in contracts that are often upgradeable, admin-controlled, and interact with AMMs at the moment of initial liquidity. Because launchpad contracts frequently act as both token issuer and primary market maker simultaneously, a single vulnerability can expose both sale proceeds and the entire circulating supply.

---

### Reentrancy via External Calls (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Sale or vesting contract transfers ETH refunds or ERC20 tokens to buyers before updating internal accounting (sold counts, refund balances, vesting schedules)
- Protocol interacts with callback tokens (ERC777, ERC721 with `onERC721Received`) in distribution or rage-quit flows
- A custom reentrancy guard reuses a business-logic variable (e.g., `rageQuitTimestamp`) that a privileged function can reset mid-execution
- Cross-contract message processing increments counters after looping over external calls, enabling replay via reentrancy

**Detection Heuristics**
- Search for `.call{value:}`, `.transfer()`, `safeTransfer()`, and `safeTransferFrom()` in sale, claim, or withdraw functions; verify state updates precede these calls
- Look for `rageQuit`, `claimRefund`, or `distributeTokens` functions using a timestamp or status flag as a reentrancy guard rather than a dedicated lock variable
- Check if any privileged role (owner, operator) can invoke a function that resets the guard variable during an active transfer loop
- Identify ERC777 token support in staking or crowdfund contracts where `tokensReceived` or `tokensToSend` hooks hand control to an arbitrary address

**False Positives**
- External calls made exclusively to immutable, trusted addresses (WETH contract) that do not propagate callbacks
- Functions protected by OpenZeppelin `ReentrancyGuard` with a dedicated `_status` lock variable
- Post-call state updates that are idempotent (e.g., marking an already-zero balance as zero)

**Notable Historical Findings**
In PartyDAO's governance contracts, a rage-quit function used `rageQuitTimestamp` as its reentrancy guard; because the protocol also exposed a `setRageQuit()` function callable by a party host, an attacker reentrant via an ERC20 transfer could reset that timestamp mid-execution and drain treasury tokens multiple times. A separate PartyDAO audit found that `TokenDistributor` was vulnerable to ERC777 `tokensToSend` hooks, allowing a malicious token to reenter and drain the distributor before balances were zeroed. In SKALE's message bridge, an incoming message counter was updated only after iterating all external calls, enabling replay of messages through reentrancy. Reserve Protocol's `redeem()` path similarly updated yield-token balances after a user-controlled swap, allowing a double-subtraction via reentrant snapshot corruption.

**Remediation Notes**
- Apply the checks-effects-interactions pattern in every sale, claim, and refund path; update `totalSold`, `refunds[user]`, and vesting state before any external transfer
- Replace custom guard variables with OpenZeppelin `ReentrancyGuard`; never reuse a business-logic timestamp or status as a lock
- For rage-quit or multi-token distribution loops, zero out per-user balances at the top of the function before iterating token transfers

---

### Precision Loss and Rounding Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Dutch auction price calculations perform division before multiplication, producing zero when elapsed time is small relative to the price drop rate
- Share-fraction migration applies `oldBalance * newSupply / oldSupply`, rounding small holders to zero when supply ratios are extreme
- Reward accumulator uses `rewardRate = reward / duration` where `duration` is years-long, discarding significant token amounts to integer truncation
- Launchpad supports tokens with fewer than 18 decimals (e.g., USDC at 6) in pricing calculations alongside 18-decimal collateral without normalization
- Voting power calculations use `(a / b) * c` order, causing unanimous-vote thresholds to be unachievable

**Detection Heuristics**
- Search for `(a / b) * c` expressions in price, reward, or voting power functions; flag any case where `a` can be smaller than `b`
- In Dutch auction contracts, verify `getPrice()` multiplies `dropPerSecond * timeElapsed` before subtracting from `startPrice`; check for a floor price guard
- In reward pools, calculate the effective distributed amount as `rewardRate * duration` and compare against `reward` to measure truncation loss
- In migration or fraction conversion functions, check for zero-result outcomes when `newSupply << oldSupply`
- Look for unsafe `uint80(msg.value)` or `uint48(timestamp)` downcasts without prior bounds checks

**False Positives**
- Protocols that enforce a minimum purchase amount large enough to guarantee non-zero results at all supported price points
- Fixed-point math libraries (PRBMath, DSMath) used consistently throughout the calculation chain
- Downcast targets validated with `require(value <= type(uintN).max)` or `SafeCast` before the cast

**Notable Historical Findings**
Nouns Builder's auction contract contained a precision error in `_computeTotalRewards` that allowed an adversary to permanently brick future auctions by manipulating the founder ownership percentage to trigger an arithmetic edge case. In Fractional Protocol, migration reduced the fraction supply so drastically that small holders received zero new tokens, effectively confiscating minority stakes. Ajna Protocol's `calculateNewRewards` divided before multiplying in a reward calculation, meaning stakers with small relative interest earned zero rewards despite legitimate participation. In veToken Finance, `notifyRewardAmount` suffered rounding loss where `reward / duration * duration < reward`, permanently locking the difference in the staking contract.

**Remediation Notes**
- In Dutch auction price functions, compute the drop as `startPrice - min(dropPerSecond * elapsed, startPrice - floorPrice)` to prevent underflow and maintain a floor
- Store `rewardRate` in a higher-precision scaled integer (e.g., `reward * 1e18 / duration`) and scale back when distributing
- In migration and fraction functions, assert `oldBalance == 0 || newBalance > 0` to surface precision loss before it silently confiscates user funds

---

### Unsafe Type Casting and Downcasting (ref: fv-sol-3)

**Protocol-Specific Preconditions**
- Sale contract stores `msg.value` in a `uint80` field without checking that payment exceeds ~1.2M ETH
- Partial-fill tracking in order matching accumulates a `uint120` numerator across multiple fills; overflow resets the fill counter, enabling overselling
- Founder percentage stored as `uint8` truncates any percentage value above 255 supplied in a `uint256` parameter
- `int8` decimals cast from `uint8` token decimals converts values 128-255 to negative numbers, breaking all price math for those tokens

**Detection Heuristics**
- Search for explicit casts to types narrower than the source: `uint80(`, `uint48(`, `uint32(`, `uint120(`, `int8(`
- For each cast, trace whether the source value is bounded by a prior `require` or `SafeCast`; flag unbounded user-supplied values (`msg.value`, function parameters)
- In order-matching contracts, check if partial-fill accumulators can overflow their storage type across multiple calls
- Look for `int8(uint8(token.decimals()))` patterns where decimals could exceed 127

**False Positives**
- Casts protected by `require(value <= type(uintN).max)` immediately before the cast
- Use of `SafeCast.toUintN()` which reverts on out-of-range values
- Values bounded by protocol invariants (e.g., percentage stored as uint8 after `require(pct <= 100)`)

**Notable Historical Findings**
OpenSea's Seaport had a `uint120` truncation in `OrderValidator` that, after enough partial fills accumulated, could reset the fill counter to zero and allow the same order to be re-filled indefinitely, enabling sellers to exceed their stated order quantity. Escher's LPDA contract stored `msg.value` as `uint80`, silently truncating payments over the type maximum and under-recording sale proceeds. Nouns Builder's founder minting loop could be manipulated via truncation in the ownership percentage cast to cause a founder to receive all base tokens rather than their stated share. Reserve Protocol's `issue()` function used an unsafe downcast in a critical amount path that, when exploited, caused a permanent denial of service on issuance.

**Remediation Notes**
- Replace all unguarded downcasts with `SafeCast` from OpenZeppelin; this is non-negotiable for `msg.value`, user-supplied amounts, and accumulated counters
- In order-fill tracking, perform the accumulation in `uint256` and only store the final value after verifying it fits in the target type
- For founder percentages, enforce `require(percentage <= 100)` before casting to `uint8`

---

### Centralization and Privileged Role Risks (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- A single EOA owner controls `setTokenAddress`, `setOperator`, or equivalent functions with no timelock, allowing them to swap underlying token mappings and drain bridge or sale proceeds
- Owner can invoke an unrestricted `execute(to, value, data)` on a voter proxy or treasury contract, enabling arbitrary token drains
- Ownership transfer is single-step: one call to `transferOwnership(newAddress)` immediately changes the owner with no confirmation from the new address
- Proxy or diamond upgrades are callable by the owner without any delay, allowing instant logic replacement

**Detection Heuristics**
- List all `onlyOwner` / `onlyAdmin` / `onlyOperator` functions; for each, determine whether it can transfer, mint, burn, or redirect user funds
- Look for `execute(address, uint256, bytes)` patterns on treasury or proxy contracts without target whitelisting
- Check `transferOwnership` for a two-step pattern (propose + accept); single-step is a red flag in any protocol holding user funds
- Verify that upgrade functions (`upgradeTo`, `diamondCut`) have a timelock enforcing a minimum delay between proposal and execution

**False Positives**
- Admin role held by a governance contract or multisig with adequate signer count and a meaningful threshold
- Admin functions gated behind a timelock with delay sufficient for users to exit (typically 48+ hours)
- Protocols in explicit bootstrap phase with disclosed admin keys that are scheduled for renouncement

**Notable Historical Findings**
SKALE's `TokenManagerEth` allowed the admin to remap any mainnet token to a schain token they controlled, then drain the deposit box by calling `exitToMain` with the remapped token. In veToken Finance, the `VoterProxy` operator could call arbitrary contract methods including `ERC20.transfer`, enabling complete drain of all protocol token holdings. Baton Launchpad's admin had unrestricted access to change fees, pause the protocol, and withdraw collected ETH without any time delay or governance check. PartyDAO's auction crowdfund allowed the NFT owner to simultaneously hold the NFT being auctioned and act as a party participant, creating an irreconcilable conflict that could permanently lock crowdfund contributor funds.

**Remediation Notes**
- Require all admin functions affecting user funds to use a timelock of at least 48 hours with on-chain proposing and execution steps
- Replace single-step `transferOwnership` with a propose-then-accept pattern; never allow `owner = newOwner` in one transaction
- Whitelist target addresses in generic `execute()` functions; do not allow arbitrary calldata to be forwarded to token contracts

---

### Auction Mechanism Flaws (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Dutch/LPDA auction uses `startPrice - (dropPerSecond * elapsed)` without a floor price, enabling underflow revert or, in an `unchecked` block, wrap-around to an astronomically high price
- Sale contract calls `selfdestruct` on completion; buyers who transact in the same block as destruction still credit ETH to the now-deleted contract
- Auction parameters (`duration`, `startPrice`, `dropPerSecond`) are mutable by the owner with no check for whether an auction is currently active
- Sale finalization path only distributes proceeds when `totalSold == maxSupply`; partial sales permanently lock ETH with no refund path

**Detection Heuristics**
- In every price function, check the subtraction `startPrice - drop`; if `drop` is not clamped before subtraction, flag as underflow risk
- Search for `selfdestruct` in sale contracts; verify no purchase path can be called after destruction in the same block or transaction
- Find all setter functions for auction parameters (duration, price curve, fee receiver); confirm they revert if `block.timestamp >= auctionStart && block.timestamp <= auctionEnd`
- In finalization logic, verify funds are distributed proportionally even when `totalSold < maxSupply`; look for refund mechanisms for overpayments

**False Positives**
- Solidity 0.8+ checked arithmetic that causes a revert (not wrap) on underflow; still may brick the contract but does not silently corrupt state
- Auction parameters settable only before `auctionStart`, enforced by an immutable start time set at deployment
- Contracts with admin-callable emergency withdrawal covering stuck funds from partial sales

**Notable Historical Findings**
Escher Protocol's LPDA contract had a price underflow path where extreme `dropPerSecond` and `startPrice` settings caused the price calculation to either revert (bricking the auction) or wrap to a near-maximum value (overcharging buyers). The same codebase allowed the `saleReceiver` to receive zero-value `buy(0)` calls after sale completion, siphoning refunds that should have returned to buyers. Nouns Builder's auction had an adversary-triggerable precision error in reward computation that permanently corrupted the auction state. PartyDAO crowdfunds exposed a scenario where the NFT owner could grief the auction by simultaneously holding the target NFT and the winning bid, causing the crowdfund to lose its NFT after settlement.

**Remediation Notes**
- Add a `floorPrice` parameter to every Dutch auction; compute `drop = min(dropPerSecond * elapsed, startPrice - floorPrice)` before subtraction
- Replace `selfdestruct` with a `saleEnded` boolean flag and a `call{value: address(this).balance}()` transfer to the receiver
- In finalization, compute proceeds as `totalSold * finalPrice` regardless of whether the cap was reached; implement per-buyer refund claims for partial sales

---

### Delegation Logic Vulnerabilities (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Governance token uses `delegates[account] == address(0)` to mean "implicitly self-delegated," but `_moveDelegateVotes` treats `address(0)` as "no votes to subtract," allowing a user's first explicit self-delegation to add votes without removing any
- Token transfers call `_afterTokenTransfer` which moves delegate votes for the receiver; if the receiver has never delegated, `delegates[to] == address(0)` causes votes to be silently destroyed
- `unstake()` requires `delegates[msg.sender] == msg.sender` before withdrawing, but `undelegate()` reverts if the delegate has an active proposal, enabling a malicious delegate to trap stakers indefinitely

**Detection Heuristics**
- In `_moveDelegateVotes(from, to, amount)`, check: if `from == address(0)`, does it skip the subtraction? If yes, first-time delegation creates votes from nothing
- In `_afterTokenTransfer`, check whether `delegates[to]` is explicitly initialized before moving votes; if not, transfers to new addresses destroy voting power
- Find all `undelegate` or delegation-reversal functions; check if they can be permanently blocked by delegate activity
- Verify that `unstake()` and `undelegate()` are independent operations with no circular dependency

**False Positives**
- Protocols that auto-delegate to self in `_mint`, ensuring `delegates[account]` is never `address(0)` for any token holder
- OpenZeppelin ERC721Votes implementations that correctly consolidate checkpoints within the same block
- Protocols where transfers are explicitly disabled (soulbound tokens)

**Notable Historical Findings**
Nouns Builder's `ERC721Votes` had three simultaneous delegation bugs: first-time self-delegation doubled voting power by skipping the subtraction from `address(0)`; `_afterTokenTransfer` destroyed voting power for recipients who had never delegated; and `_transferFrom` could be called repeatedly to increase a user's voting power indefinitely without acquiring new tokens. FrankenDAO's staking contract allowed a delegate to maintain a perpetual active proposal, permanently preventing delegators from undelegating and withdrawing their staked tokens. PartyDAO's crowdfund allowed self-delegated users' delegation to be hijacked during the contribution phase, silently transferring their governance weight to another party.

**Remediation Notes**
- Auto-delegate to self in `_mint` and in `_afterTokenTransfer` when `delegates[to] == address(0)`; never use `address(0)` as a meaningful delegation state
- Remove all conditions on `undelegate()` that depend on the delegate's state; undelegation must always be available unconditionally
- In `_moveDelegateVotes`, treat `from == address(0)` as equivalent to `from == account` (implicit self-delegate) to ensure votes are properly subtracted

---

### Flash Loan Checkpoint Manipulation (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Checkpoint or snapshot mechanism records voting power at a block number; `getAtBlock()` returns the first checkpoint value in the block rather than the last, making flash-loan-inflated snapshots queryable after the loan is repaid
- Staking contract allows same-block stake and exit with no minimum holding period, enabling a flash loan to create and immediately destroy a large checkpoint
- Collateral status or price-sensitive decisions use AMM spot prices (immediately manipulable by a flash loan trade) rather than TWAP
- ETH crowdfund contribution snapshot is taken at block number rather than excluding the current block

**Detection Heuristics**
- In `getAtBlock(blockNumber)`, check whether the binary search returns the first or last checkpoint at that block number; if first, same-block manipulations are queryable
- Look for `stake()` / `exit()` pairs callable within the same transaction with no `require(block.number > lastStakeBlock[msg.sender])` guard
- Find all price queries in collateral status or auction settlement code; check whether they use `getReserves()` (spot) or a time-weighted average
- In ETH crowdfund contracts, verify contribution snapshots exclude the current block to prevent same-transaction contribution and proposal control

**False Positives**
- Checkpoint implementations that update the last entry for the current block rather than creating a new one (correct OpenZeppelin behavior)
- A `require(block.number > lastStakeBlock[msg.sender])` guard between deposit and first-use
- TWAP oracles with windows long enough that a single flash-loan trade moves them by a negligible amount

**Notable Historical Findings**
Telcoin's staking contract allowed flash-borrowed TEL tokens to be staked and exited in the same block; because the checkpoint returned the first (pre-exit) value for that block, a querier after the block saw a large staked balance that no longer existed, enabling reward manipulation. PartyDAO's ETH crowdfund had a flash-loan attack path where an attacker contributed with flash-loaned ETH to obtain enough voting power to unilaterally control the party, then repaid the loan while retaining governance control. Reserve Protocol's `CurveVolatileCollateral` used a spot price for collateral status checks; a flash loan could temporarily push the price below the depeg threshold, triggering a basket rebalance at unfavorable rates.

**Remediation Notes**
- Fix `getAtBlock` to return the last (most recent) checkpoint at a given block; this is `checkpoints[account][pos - 1].votes` where `pos` is found via binary search for the last entry `<= blockNumber`
- Add `require(block.number > lastStakeBlock[msg.sender], "Same-block exit not allowed")` in any exit or withdrawal function following a deposit
- For collateral status checks, use a TWAP oracle with a window of at least 30 minutes; never use `getReserves()` spot price for decision-making

---

### Governance Voting Power Manipulation (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- `propose()` snapshots quorum votes using `token.totalSupply()` at the current block rather than a checkpointed past supply, allowing a proposer to mint or acquire tokens in the same transaction to reduce effective quorum
- Multiple state changes in a single block (stake, unstake, transfer) each write a new checkpoint rather than updating the existing one, causing `getPastVotes` to return incorrect intermediate values
- NFT transfer is not restricted during an active vote; a voter can transfer the NFT to a second wallet in the same block as the proposal, voting twice against a single snapshot
- `unstake()` decreases voting power by the token's current base value rather than the value recorded at stake time, creating discrepancies when staking multipliers change

**Detection Heuristics**
- In `propose()` or `quorum()`, look for `totalSupply()` calls without a `getPastTotalSupply(block.number - 1)` offset
- In `_writeCheckpoint`, check whether the function creates a new array entry on every call or updates the existing entry when `blockNumber == block.number`; the former enables multi-checkpoint manipulation
- Look for `accept()` or `castVote()` that reads voting power at `proposal.voteStart` without requiring `block.timestamp > voteStart`
- In staking contracts, trace `stake()` to confirm it records `stakedVotingPower[tokenId] = getTokenVotingPower(tokenId)` so `unstake()` can use the stored value rather than the current multiplied value

**False Positives**
- Proposals that read `getPastVotes(account, block.number - 1)` or equivalent, ensuring current-block manipulation is excluded
- Checkpoint writers that update `checkpoints[id - 1]` when `checkpoints[id - 1].timestamp == block.timestamp`
- Governance contracts with a vetoer role or guardian capable of canceling proposals created via manipulation

**Notable Historical Findings**
Nouns Builder had at least five simultaneous voting-power exploits including double-delegation, infinite-power-via-transfer, and a quorum calculation that did not account for burned tokens, meaning a sufficiently motivated attacker could pass proposals with no legitimate support. PartyDAO suffered a critical bug where `totalVotingPower` was inflated in `_finalize()` by counting contributor voting weight twice, and a separate bug allowed a user to veto the same proposal repeatedly by transferring and reclaiming their governance NFT. FrankenDAO's community voting power calculation was subject to precision loss, and delegates could arbitrarily lower quorum by manipulating the delegation graph. Livepeer's vote-override path incorrectly identified transcoders, allowing a delegator to reduce another participant's vote tally without any legitimate basis.

**Remediation Notes**
- Always snapshot quorum and threshold values at `block.number - 1` or via `getPastTotalSupply`; never read live supply during proposal creation
- Checkpoint writers must update the most recent entry when `checkpoints[last].blockNumber == block.number`; adding a new entry for the same block is the root cause of most multi-checkpoint exploits
- Record each staker's voting power at stake time in a `stakedVotingPower[tokenId]` mapping; use that stored value, not a recomputed current value, in `unstake()`

---

### Reward Distribution Accounting Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Reward accumulator is never updated during the period when `totalSupply == 0` (between sale end and first staker), permanently locking that interval's rewards in the contract
- `claimRewards(fromEpoch, toEpoch)` accepts a `toEpoch` parameter without validating it against the current epoch, allowing users to mark future epochs as claimed before those rewards are allocated
- Admin changes reward rate, weight, or duration without first calling `updateReward(address(0))`, recalculating historical accruals at the new rate retroactively
- Reward token address is the same as the staking token address, creating circular accounting that inflates reported reward balances

**Detection Heuristics**
- In `rewardPerToken()`, look for `if (totalSupply() == 0) return rewardPerTokenStored` - this is correct for per-token rate but rewards emitted during that window are lost; check whether there is a recovery or queuing mechanism
- Find all `setRewardWeight`, `setRewardRate`, `notifyRewardAmount` functions; verify each one calls `updateReward(address(0))` or equivalent before changing the parameter
- In epoch-based claim functions, check whether `toEpoch <= currentEpoch` is asserted
- Search for `extraRewards.push(rewardToken)` without a duplicate-check loop; also check `rewardToken != stakingToken`

**False Positives**
- Protocols where `totalSupply == 0` is structurally impossible (minimum stake enforced at launch, or protocol treasury always holds tokens)
- Epoch boundaries strictly enforced by block timestamps that prevent future-epoch claims
- Admin functions that include `updateReward` calls as their first line

**Notable Historical Findings**
veToken Finance's staking pool permanently lost rewards whenever `totalSupply` was zero during a reward period, and separately allowed duplicate entries in the `extraRewards` array, meaning a reward token could be distributed multiple times. Ajna Protocol's epoch-based reward system allowed claiming from future epochs, which pre-emptively marked those epochs as claimed and prevented users from ever receiving those rewards when the epoch actually arrived. Reserve Protocol's staking contract allowed rewards to be claimed during a pause or frozen state, letting an actor who staked just before an unfreeze absorb the bulk of rewards that had accrued during the frozen period. Locke Protocol's stream reward calculation used truncated division, consistently rounding reward amounts to zero for users with small relative stake.

**Remediation Notes**
- During zero-supply periods, queue emitted rewards in a `queuedRewards` accumulator; distribute queued rewards to the first stakers, or allow the owner to recover them to the treasury
- Gate `claimRewards(fromEpoch, toEpoch)` with `require(toEpoch <= currentEpoch)` and `require(!isEpochClaimed[msg.sender][epoch])` for each epoch in the range
- Every reward parameter setter must call `_updateReward(address(0))` as its first line, before modifying any rate or weight variable

---

### Unsafe ETH Transfer Patterns (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Sale or refund contract calls `payable(recipient).transfer(amount)`, forwarding only 2300 gas; fails silently or reverts for recipients that are multisigs (Gnosis Safe), proxy contracts, or any contract with a non-trivial `receive()` function
- Withdrawal function has no fallback path: if the ETH send fails, the user's recorded balance is never credited to an alternative mechanism and the funds become permanently inaccessible
- Assembly blocks in cross-chain bridge or relay contracts use a hardcoded gas stipend in `call` instructions, producing the same 2300-gas restriction as `.transfer()`

**Detection Heuristics**
- Search for `.transfer(` and `.send(` patterns on `payable` addresses throughout the codebase
- Identify every location where an ETH transfer failure causes the entire transaction to revert without a pull-based fallback option; trace whether user funds are recoverable if that path is permanently broken
- Look for `assembly { let success := call(2300, ...) }` blocks that hardcode the gas stipend

**False Positives**
- Recipients that are provably EOAs (extremely rare to guarantee in practice)
- Contracts that wrap failed ETH transfers by depositing WETH and transferring that instead
- Pull-based refund patterns where users call a separate `claimRefund()` function

**Notable Historical Findings**
Multiple launchpad-adjacent protocols (Escher, Fractional, Forgotten Runes, LarvaLabs Meebits) independently used `.transfer()` or `.send()` for refund and withdrawal logic; in each case, multisig treasury wallets or proxy recipients failed to receive funds because 2300 gas was insufficient for their `receive()` implementations. Post-EIP-2929 storage access cost increases make `.transfer()` increasingly likely to fail even for contracts that previously worked. The fix is universally the same but was rediscovered in every codebase rather than addressed as a known pattern.

**Remediation Notes**
- Replace all `.transfer()` and `.send()` calls with `(bool success, ) = payable(recipient).call{value: amount}("")`; check `success`
- Pair low-level `call` with `ReentrancyGuard` since forwarding all gas reintroduces reentrancy risk
- For batch refund flows, implement a pull pattern: store amounts in a mapping and provide a `claimRefund()` function; do not push ETH to arbitrary addresses in loops

---

### Unsafe ERC20 Token Handling (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Sale contract calls `IERC20(token).transfer(recipient, amount)` with a `require()` wrapper; tokens like USDT on mainnet do not return a boolean, causing the call to revert for an unexpected ABI reason rather than a logical failure
- Deposit function credits `amount` to the user's balance without measuring the actual received amount; fee-on-transfer tokens (or tokens that later enable fees) result in the contract owing more than it holds
- `approve()` called on a token like USDT with a non-zero current allowance reverts; contract cannot interact with USDT after any partial-use of an existing approval

**Detection Heuristics**
- Search for `IERC20(token).transfer(`, `IERC20(token).transferFrom(`, and `IERC20(token).approve(` that are not wrapped by `SafeERC20`
- Find deposit functions that record `userDeposits[msg.sender] += amount` without a `balanceBefore` / `balanceAfter` delta check
- Look for `IERC20(token).approve(spender, amount)` calls without a preceding `approve(spender, 0)` reset

**False Positives**
- Protocols that explicitly support only WETH, DAI, or USDC v2 and enforce this at the smart contract level with a token whitelist mapping
- Codebases that import and use `SafeERC20` consistently with `using SafeERC20 for IERC20`
- Protocols on chains where all relevant tokens conform to the ERC20 boolean return requirement

**Notable Historical Findings**
Multiple launchpad protocols (Holograph, Telcoin, Forgotten Runes, veToken Finance) independently called non-safe `IERC20.transfer` or `transferFrom`, breaking compatibility with USDT and other tokens that omit the boolean return. The veToken Finance audit found that fee-on-transfer discrepancies caused accounting overstatements across multiple functions, meaning the protocol could owe users more than it held. SKALE's bridge explicitly did not handle rebasing or deflationary tokens, creating a class of tokens that could be deposited but never withdrawn at their true value.

**Remediation Notes**
- Use `SafeERC20` from OpenZeppelin for every token interaction; replace `require(token.transfer(...))` with `token.safeTransfer(...)` unconditionally
- In any deposit function, compute `actualReceived = balanceAfter - balanceBefore` and use that value for all accounting rather than the passed-in `amount`
- For USDT-style approval resets, use `IERC20(token).forceApprove(spender, amount)` (OpenZeppelin v5) or manually set allowance to zero first

---

### Selfdestruct and Implementation Destruction Risks (ref: fv-sol-7)

**Protocol-Specific Preconditions**
- Fixed-price sale contract uses `selfdestruct(payable(receiver))` at sale completion; calls made to the contract address in the same block (before end-of-block execution) still succeed and send ETH to the now-empty address
- Factory deploys implementation contracts for EIP-1167 minimal proxies without initializing them; any caller can invoke `initialize()` on the bare implementation, claim ownership, and call `execute(selfdestruct payload)` via `delegatecall` to destroy the logic for all clones
- Protocol's correctness relies on `selfdestruct` returning ETH and zeroing code; EIP-4758 deprecation changes this behavior, breaking assumptions in production contracts

**Detection Heuristics**
- Search for `selfdestruct(` in any contract that is or could be an implementation behind a proxy
- Check all factory contracts: for each deployed implementation, verify `initialize()` is called atomically in the same deployment transaction, or that the constructor calls `_disableInitializers()`
- Search for `delegatecall` on user-supplied targets in any privileged function of an implementation contract
- Check contract documentation or comments for reliance on `selfdestruct` ETH-forwarding behavior under EIP-4758

**False Positives**
- `selfdestruct` used in a contract that is never a delegatecall target and holds no user funds after destruction
- Implementation contract initialized in the same deployment transaction, with no window for a front-run
- Contracts that use OpenZeppelin `_disableInitializers()` in the constructor to permanently prevent initialization of the bare implementation

**Notable Historical Findings**
Escher Protocol's fixed-price sale contract called `selfdestruct` at the end of a completed sale; because Solidity executes `selfdestruct` at end-of-transaction, a buyer who called `buy()` in the same block as completion successfully sent ETH to the destroyed address with no corresponding token mint. Fractional Protocol's vault implementation was left uninitialized after factory deployment, allowing an attacker to call `initialize()` directly on the implementation, become its owner, and execute a `delegatecall` to a contract containing `selfdestruct`, destroying the logic for all existing vaults.

**Remediation Notes**
- Remove all `selfdestruct` usage from sale contracts; replace with a `saleEnded = true` flag, a state-check guard at the top of `buy()`, and an explicit `call{value: balance}()` transfer to the receiver
- In every factory pattern, call `implementation.initialize(address(this))` or `_disableInitializers()` in the same deployment transaction; never deploy an uninitialized implementation

---

### Frontrunning and MEV Exploitation (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Two-step NFT deposit (external `offerForSale` then protocol `addCollateral`) does not verify `msg.sender == nftOwner` in the second step; any observer can front-run and deposit someone else's offered NFT to their own account
- Slashing or penalty function is callable by the owner and publicly visible in the mempool; the target can observe the transaction and front-run with a full withdrawal
- Authorization revocation is a single transaction; the soon-to-be-unauthorized actor can front-run by performing their malicious action before the revocation lands
- State-dependent validation (hash check, balance check) can be invalidated by a concurrent transaction, causing legitimate user transactions to fail while a front-runner's transaction succeeds

**Detection Heuristics**
- Find two-step deposit or approval flows where step 2 is callable by any address; check whether step 2 validates `msg.sender` against the intent of step 1
- Find `slash`, `kick`, `penalize`, and `revoke` functions callable by a single privileged address without a prior pause or freeze; these are universally front-runnable
- Look for hash-based state validation (e.g., `require(currentHistoryHash == historyHash)`) where a concurrent transaction by another party changes the hash
- Check whether sandwich attack vectors exist on AMM interactions at launch (liquidity seeding, initial price setting)

**False Positives**
- Protocols that route transactions through Flashbots or a private mempool, making front-running economically infeasible
- Administrative functions guarded by a timelock that provides adequate notice to users
- L2 deployments with a centralized sequencer providing FIFO ordering guarantees

**Notable Historical Findings**
Ajna Protocol's CryptoPunks pool was vulnerable to deposit front-running because the two-step offer-then-deposit flow did not verify NFT ownership in the second call, allowing any observer to steal a depositor's CryptoPunk by front-running the `addCollateral` transaction. In Holograph, operators who were selected for a bridging job could be front-run by other operators who bribed validators for priority inclusion, stealing the bond amount. Baton Launchpad had no protection against a malicious NFT creator front-running a user's NFT creation transaction to take over the NFT configuration. Reserve Protocol's `Furnace.melt()` function was sandwichable, allowing an attacker to profit by placing buy-melt-sell transactions around a legitimate melt call.

**Remediation Notes**
- In two-step NFT deposit flows, verify `nftContract.ownerOf(tokenId) == msg.sender` inside the second step rather than relying on the external offer mechanism alone
- Implement exit cooldowns (`requestExit()` + delay + `executeExit()`) to prevent front-running of slash or penalty transactions
- For functions with state-dependent hash checks, add a caller-supplied `deadline` parameter and revert if `block.timestamp > deadline`

---

### Gas Griefing and EIP-150 Exploitation (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- `try/catch` block catches failures from a high-gas external call (`token.mint()`, batch operation) and performs a critical state change (`_pause()`) in the `catch` branch; an attacker can supply exactly enough gas for 1/64 to cover the `catch` branch while deliberately causing the `try` branch to run out of gas
- Cross-chain job execution checks `gasleft() >= gasLimit` but the EIP-150 63/64 rule means the inner call receives `gasleft() * 63 / 64`, not `gasleft()`, making the check insufficient
- Recursive `getImageURIForHat` or similar tree-traversal functions have no maximum depth, allowing a sufficiently deep hierarchy to exhaust gas and permanently brick the function
- User-supplied `gasLimit` parameter for cross-chain bridge messages has no upper bound relative to the destination chain's block gas limit

**Detection Heuristics**
- Search for `try/catch` blocks; for each, identify what the `catch` branch does. If it pauses the protocol, slashes, or performs any irreversible state change, the `try` branch is a griefing vector via deliberate OOG
- Calculate the gas cost of the `catch` branch; if it is less than `(block.gaslimit / 64)`, the attack is feasible
- Search for `gasleft() >= gasLimit` before forwarded calls; check whether the comparison accounts for the 63/64 reduction
- Search for recursive functions without a `maxDepth` parameter or explicit depth counter

**False Positives**
- `catch` branches that only emit events or perform no state changes
- Bounded external call gas costs that cannot be inflated regardless of input
- Recursion bounded by design (e.g., maximum tree depth enforced at node creation time)

**Notable Historical Findings**
Nouns Builder's `_createAuction()` used `try token.mint()` with `_pause()` in the catch; an attacker who provided carefully calculated gas could cause `mint()` to fail with OOG while the remaining 1/64 sufficed for `_pause()`, effectively bricking the auction contract without any tokens being minted. Holograph's bridge execution framework had a gas check that did not account for EIP-150, meaning an operator could intentionally fail jobs and get slashed opponents by providing gas amounts just below the true requirement. Hats Protocol had an unbounded recursive URI lookup that traversed parent hats up the tree with no depth limit, enabling any hat tree that exceeded the gas limit to permanently lose URI resolution.

**Remediation Notes**
- In `try/catch` blocks with critical state changes in `catch`, differentiate error types: only act on known error selectors and revert on unknown errors (which include out-of-gas); replace generic `catch { _pause(); }` with `catch (bytes memory err) { if (bytes4(err) == KNOWN_ERROR_SELECTOR) { _pause(); } else { revert(...); } }`
- For gas forwarding checks, use `require(gasleft() * 63 / 64 >= gasLimit + OVERHEAD)` rather than `require(gasleft() >= gasLimit)`
- Bound all recursive functions with an explicit `maxDepth` counter passed as a function argument or defined as a protocol constant

---

### Oracle and Price Feed Vulnerabilities (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Launchpad or staking protocol deployed on Arbitrum or Optimism does not check the L2 sequencer uptime feed before consuming Chainlink prices; stale prices served during a sequencer outage drive incorrect liquidations or trade settlements
- Oracle timeout handling returns `(0, FIX_MAX)` rather than reverting or pausing, causing assets to be sold at an effective price of zero when the feed goes stale
- `refresh()` or price-update function reverts entirely when the underlying Chainlink feed is deprecated, bricking all protocol functionality that depends on price updates
- Collateral valuation uses an AMM spot price (`getReserves()`) that can be moved within a single transaction via flash loan

**Detection Heuristics**
- Search for `latestRoundData()` calls; verify all five return values are consumed and validated (`roundId`, `answer > 0`, `updatedAt > 0`, `answeredInRound >= roundId`, `block.timestamp - updatedAt < MAX_STALENESS`)
- On Arbitrum/Optimism deployments, verify the sequencer uptime feed is queried before any price consumption and that a grace period is enforced after sequencer restart
- Find any price function that returns a zero or sentinel value on oracle failure and trace whether that value propagates into trade or auction settlement logic
- Look for `catch { revert(...) }` around oracle calls; the protocol should gracefully degrade (mark collateral as IFFY, pause trading) rather than bricking

**False Positives**
- L1 Ethereum deployments with no sequencer concern
- Protocols using TWAP oracles with sufficiently long windows that flash-loan manipulation has negligible impact
- Oracle wrapper contracts that centralize all validation checks before the protocol consumes prices

**Notable Historical Findings**
Reserve Protocol had multiple oracle-related findings: `lotPrice()` returned the initial price rather than the most recent valid price during a timeout window, causing assets to be sold far below fair value; `refresh()` reverted entirely on Chainlink feed deprecation, permanently disabling the affected collateral plugin; and an oracle timeout path explicitly returned `(0, FIX_MAX)` which triggered a sell-off of RSR at zero price. Bond Protocol's integration on Arbitrum did not check sequencer uptime, allowing price data from before a sequencer outage to be used as if current. Reserve's CurveVolatileCollateral used a Curve spot price that was vulnerable to the well-known read-only reentrancy via Curve's `remove_liquidity` callback.

**Remediation Notes**
- Implement a single, reusable `getValidatedPrice(feed)` internal function that checks sequencer uptime, validates all five `latestRoundData` return values, normalizes decimals dynamically via `feed.decimals()`, and reverts with a specific error rather than returning a sentinel
- On oracle timeout, mark collateral as `IFFY` and pause trading rather than returning zero or a stale price
- For collateral backed by Curve LP tokens, check for the Curve read-only reentrancy condition before consuming pool prices

---

### Signature and Hash Verification Issues (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- `ecrecover` is called without checking whether the returned address is `address(0)`; an invalid signature with non-standard `v` value returns `address(0)`, and if a hat or governance role is owned by `address(0)` (burned/unassigned), the check passes
- Signatures are verified against `keccak256(abi.encodePacked(target, data))` without including `nonce`, `chainId`, or `verifyingContract`, enabling replay across chains, deployments, or after state changes
- Order or proposal IDs are derived from `bytes4(keccak256(...))` (truncated to 4 bytes), making collision attacks feasible for sufficiently motivated adversaries
- Multisig threshold is checked by counting valid signers, but the counting loop does not reject `address(0)` returns from `ecrecover`, allowing invalid signatures to count toward threshold

**Detection Heuristics**
- Search for raw `ecrecover(` calls not wrapped by OpenZeppelin `ECDSA.recover()`; verify the result is compared against `address(0)` before use
- Find all signature verification functions; check for EIP-712 domain separator including `chainId` and `verifyingContract`; check for nonce increment on each use
- Look for `bytes4(keccak256(...))` or any sub-32-byte hash used as a unique identifier in security-critical contexts (proposal IDs, order hashes)
- In multisig signer-counting loops, verify that `ecrecover` return values of `address(0)` are explicitly rejected

**False Positives**
- Signature verification using `ECDSA.recover()` from OpenZeppelin, which handles `address(0)` returns internally
- Full EIP-712 typed structured data with domain separator containing all required fields
- Replay protection handled at a higher protocol layer (e.g., per-user nonce incremented on every signed action)

**Notable Historical Findings**
Hats Protocol's multisig integration passed any signature whose recovered signer was `address(0)` as valid if `address(0)` happened to wear the requisite hat (a common state for unassigned hats), allowing an attacker to construct entirely invalid signatures that satisfied the safe's threshold. OpenSea's Seaport had incorrect pointer arithmetic in order hash encoding that caused the 0x04 `sha256` precompile to process wrong data, resulting in orders being matched against corrupted hashes. zkSync's bridge did not enforce EIP-155 chain ID in transaction signatures, allowing operators to replay transactions across chains at favorable times. Holograph's bridged job recovery mechanism could not recover failed jobs because the job data hash was tied to the original submission block, making re-execution structurally impossible.

**Remediation Notes**
- Replace all `ecrecover(` calls with `ECDSA.recover()` from OpenZeppelin; additionally, explicitly reject `address(0)` as a valid signer in all verification logic
- All signature schemes must include `chainId`, `verifyingContract`, `nonce`, and a typed action identifier following EIP-712; never sign over only `(target, data)` without these fields
- Use full 32-byte keccak256 hashes for all unique identifiers; truncated hashes are only acceptable for non-security-critical purposes such as event indexing
