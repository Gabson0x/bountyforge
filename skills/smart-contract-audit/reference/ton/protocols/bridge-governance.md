# Bridge and Governance Security Patterns (TON)

> Applies to: cross-chain bridge contracts on TON, TON-to-EVM bridges, Jetton bridge contracts, DAO governance contracts, multisig-controlled protocols, proposal-and-vote governance, timelock controllers, admin key management, any FunC or Tact contract processing messages from external chains or governing protocol parameter changes

## Protocol Context

Bridge contracts on TON must enforce message uniqueness across the async message model: the same cross-chain transfer message can potentially be delivered multiple times due to network retries or relay failures, and without an on-chain deduplication dictionary, each delivery mints tokens. TON governance contracts face the standard flash governance attack from EVM but with the added complexity that vote-weight snapshots must be anchored to a specific seqno or timestamp before voting opens, since TON Jetton balances change continuously via messages. Governance execution on TON is also async, meaning the timelock countdown should begin after the message is processed, not when it is sent.

## Bug Classes

---

### Bridge Message Replay

**Protocol-Specific Preconditions**

- Bridge claim handler does not maintain a dictionary of processed message hashes or nonces
- The same cross-chain transfer proof can be submitted multiple times; each submission mints tokens on the TON side without checking whether it was already processed
- Bridge relay can submit duplicate messages during network partitions or bridge software restarts; no deduplication at the protocol level

**Detection Heuristics**

- Find the bridge claim or mint handler; check for `throw_unless(error::already_processed, ~ dict_get(processed_messages, msg_hash))` before minting
- Verify that after processing, the message hash is stored in the dictionary: `processed_messages = dict_set(processed_messages, msg_hash, true)`
- Check whether the processed messages dictionary has a bounded size or is pruned; an unbounded dictionary grows indefinitely and increases storage fees; verify this is acceptable or that a TTL-based pruning is implemented
- Verify that the message hash is computed from all fields that uniquely identify the transfer (source chain, source address, destination address, amount, nonce) and not just a subset

**False Positives**

- Message hash checked against processed dictionary before minting and stored after minting in the same handler
- Bridge uses a committee attestation with threshold signatures; each valid proof is unique by construction and cannot be replayed

---

### Bridge Supply Invariant Violation

**Protocol-Specific Preconditions**

- Total minted supply on the TON side can exceed the locked supply on the source chain due to decimal conversion rounding, replay, or a missing supply cap
- No `total_minted` counter maintained and compared against the authorized `total_locked` value reported by the bridge authority
- Decimal conversion between the source chain's token decimals and TON Jetton decimals rounds up on mint and down on burn, allowing a rounding profit per round-trip

**Detection Heuristics**

- Check whether the bridge contract maintains a `total_minted` counter and verifies `total_minted <= authorized_locked_amount` before each mint
- Verify the decimal conversion math for round-trip correctness: minting and burning the same amount should leave both sides unchanged; test with edge-case amounts
- Check the supply cap check path: if the bridge authority reports a new locked amount, verify the report is authenticated and cannot be inflated by the reporter
- Verify that the bridge contract's Jetton minting authority is restricted to the bridge contract itself and cannot be invoked by any other address

**False Positives**

- Total minted is tracked and capped to the authorized locked amount at every mint instruction
- Decimal conversion uses floor on mint (conservative) and ceiling on burn (also conservative for the protocol); round-trip never produces more than the original amount

---

### Governance Flash Vote

**Protocol-Specific Preconditions**

- Vote weight read from the voter's current Jetton balance at voting time rather than from a historical snapshot taken before the voting period opened
- Attacker can purchase tokens in a message preceding the vote, vote with inflated weight, and sell tokens in a subsequent message - all in the same block or short window
- No minimum holding period required before a holder is eligible to vote

**Detection Heuristics**

- Check the vote handler for how it reads `voter_weight`: is it queried from the Jetton wallet's current balance or from a snapshot stored at vote initialization?
- Verify that the voting period initialization stores a snapshot seqno or timestamp and the vote handler computes weight from balances at that seqno, not current balances
- Check whether token transfers are blocked during an active vote; if not, balance at vote time may differ from balance at vote submission time
- Calculate the maximum weight an attacker could acquire with a flash loan and whether that exceeds the quorum threshold

**False Positives**

- Vote weight computed from a historical snapshot: balance as of the block before voting opened, stored in the proposal or read from a checkpoint contract
- Token transfers during active vote period do not affect votes already cast; new tokens acquired after vote submission cannot change the recorded weight

---

### Proposal Execution Without Timelock

**Protocol-Specific Preconditions**

- Governance proposals execute immediately upon reaching the vote threshold without a delay period for users to review and exit
- `timelock_delay` field in the governance contract is zero or not enforced
- Proposal execution is triggered by the passing-vote message itself rather than by a separate execution message sent after the timelock expires

**Detection Heuristics**

- Find the proposal execution path; check whether `throw_unless(error::too_early, now() >= proposal.passed_at + TIMELOCK_DELAY)` is enforced before execution
- Verify that the timelock delay start is set to the time the proposal passes, not the time it was submitted; a proposal submitted with a future execution time that skips the timelock is equivalent to no timelock
- Check whether there is a cancellation mechanism during the timelock window that allows governance to halt execution if a malicious proposal is detected after passing
- Verify that `TIMELOCK_DELAY` is a governable parameter and that reducing it requires a proposal subject to its own timelock

**False Positives**

- Execution requires a separate `op::execute_proposal` message sent after `now() >= passed_at + timelock_delay`; passing the vote alone does not execute
- Timelock delay is a contract constant that cannot be changed without a program upgrade; its value is hardcoded and reviewed at each upgrade
