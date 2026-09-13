# Governance and Authority Security Patterns (Sui/Move)

> Applies to: Move-based governance modules, AdminCap and UpgradeCap management, DAO voting on Sui, proposal-and-vote modules, protocol parameter updates, multisig-controlled protocols, any Move module managing privileged capabilities, bridge governance, ZK-based governance verification

## Protocol Context

Governance on Sui differs from EVM governance in a fundamental way: privileged operations are gated by capability objects (`AdminCap`, `UpgradeCap`, `GovernanceCap`) rather than by address-based role checks. The security model depends on who holds these capability objects and how they can be transferred. `UpgradeCap` is particularly important: holding it grants the ability to upgrade any module in the package, and if it is stored as a shared object or wrapped in a governance module, the upgrade path must be secured by a timelock and multisig. Flash governance is possible on Sui via PTB: borrow governance tokens, vote, redeem - unless vote weight is anchored to a historical snapshot rather than current balance.

## Bug Classes

---

### UpgradeCap Not Protected (ref: fv-mov-3-cl1)

**Protocol-Specific Preconditions**

- `UpgradeCap` stored as a shared object accessible to any transaction, or held by a single-keypair address rather than a multisig or governance module
- `UpgradeCap` with `policy = COMPATIBLE` allows adding new functions and changing behavior; policy not restricted to `ADDITIVE_ONLY` or `DEP_ONLY` to limit upgrade scope
- No timelock between upgrade proposal and execution; upgrade can be applied in a single transaction from the `UpgradeCap` holder

**Detection Heuristics**

- Find the `UpgradeCap` object at deployment; check its owner: is it a single address, a multisig, or a governance module?
- Check the `UpgradeCap.policy` field: `0` (compatible), `128` (additive-only), `192` (dep-only); less restrictive policies allow more dangerous upgrades
- Verify the upgrade path: if `UpgradeCap` is wrapped in a governance module, check the voting threshold, timelock delay, and cancellation mechanism
- Check whether `package::make_immutable(upgrade_cap)` has been called to permanently lock the package; if so, upgrades are impossible

**False Positives**

- `UpgradeCap` is wrapped in a governance module with a documented threshold, independent signers, and an enforced timelock
- `package::make_immutable` has been called; the `UpgradeCap` is consumed and the package is permanently immutable

---

### AdminCap Transfer Without Two-Step Confirmation (ref: fv-mov-3-cl1)

**Protocol-Specific Preconditions**

- `AdminCap` transfer is a single-step operation: current holder calls `transfer::transfer(admin_cap, new_address)` and the cap immediately moves
- A typo in `new_address` permanently loses the `AdminCap`; no recovery mechanism exists
- No two-step pattern (propose + accept) enforced; the new address cannot reject or confirm the transfer

**Detection Heuristics**

- Find all functions that transfer `AdminCap` or equivalent privileged capability objects; check whether they require the new owner to explicitly accept via a separate transaction
- Verify a two-step pattern: (1) `propose_admin_transfer(cap, new_address)` stores pending address, (2) `accept_admin_transfer(cap)` requires signature of the pending new address
- Check whether there is an emergency revoke function that allows the current holder to cancel a pending transfer before it is claimed
- Verify that the pending new address is validated as non-zero before being stored

**False Positives**

- Two-step transfer pattern implemented: pending address stored, acceptance requires the new address's signature
- Transfer is mediated by a governance module requiring a vote; no single-party transfer is possible

---

### Flash Governance Vote via PTB

**Protocol-Specific Preconditions**

- Vote weight read from the voter's current token balance at voting time rather than a historical snapshot taken before the voting period opened
- PTB allows: borrow governance tokens, vote with inflated weight, sell tokens, repay flash loan - all in one atomic transaction block
- No minimum holding period before a token holder becomes eligible to vote

**Detection Heuristics**

- Check how vote weight is computed in the voting function: is it `coin::value(&voter_coin)` at call time, or a snapshot balance from a past epoch?
- Verify that voting weight comes from a checkpoint object or a snapshot balance stored at proposal creation time, not from live coin balance
- Check whether token transfers are blocked during an active vote period; if not, balance at vote submission time may differ from the balance at any reference point
- Calculate whether a flash-loan-financed vote can exceed the quorum threshold; if so, flash governance is a viable attack

**False Positives**

- Vote weight derived from a snapshot taken before voting opened: balances are checkpointed in a `VoterCheckpoint` object at proposal creation
- Governance tokens have a transfer lock during active vote periods; moving tokens while a vote is open is rejected by the token module

---

### Proposal Execution Without Timelock

**Protocol-Specific Preconditions**

- Governance proposals execute immediately upon reaching the vote threshold
- `proposal.execute_after_ms` is zero or not checked before execution
- Emergency execution path bypasses the normal timelock without requiring a higher approval threshold

**Detection Heuristics**

- Find the proposal execution function; verify `assert!(clock::timestamp_ms(clock) >= proposal.execute_after_ms, ERROR_TIMELOCK_ACTIVE)` before any state mutation
- Check that `execute_after_ms` is set to `passed_at_ms + TIMELOCK_DELAY_MS` when the vote passes, not when the proposal was created
- Verify there is a cancellation function callable during the timelock window that requires a governance vote or a privileged cap to cancel a malicious proposal
- Check whether `TIMELOCK_DELAY_MS` is a mutable parameter; if so, verify reducing it requires its own governance proposal subject to the same timelock

**False Positives**

- Execution requires `clock::timestamp_ms(clock) >= proposal.execute_after_ms` enforced as the first check in the execution function
- Timelock delay is a module constant that cannot be changed without a package upgrade; its value is reviewed at each upgrade

---

### Bridge Message Replay

**Protocol-Specific Preconditions**

- Bridge contract processes inbound messages without storing or checking a message hash or nonce, allowing the same bridge transfer to be submitted multiple times
- Each accepted submission mints tokens on the Sui side without checking whether the originating lock event was already processed
- No `Table<vector<u8>, bool>` or equivalent processed-message registry maintained in the bridge contract's shared state

**Detection Heuristics**

- Find the bridge claim or mint function; check whether `assert!(!table::contains(&processed_messages, message_hash), ERROR_ALREADY_PROCESSED)` is called before any token minting
- Verify that `message_hash` is stored: `table::add(&mut processed_messages, message_hash, true)` after successful processing, not only on error paths
- Check that `message_hash` is derived from immutable fields of the bridge message (source chain ID, source tx hash, amount, recipient) and not from mutable fields the submitter controls
- Verify the processed-message table is a shared object accessible to all validators; using an owned object allows the holder to reset it

**False Positives**

- Every bridge claim checks for and stores the message hash before any state mutation; the table is append-only with no deletion path
- Bridge uses a committee-signed attestation with multi-sig threshold; verify committee key decentralization and threshold adequacy

---

### ZK Proof Nullifier Not Enforced

**Protocol-Specific Preconditions**

- Protocol uses ZK proofs (Groth16, PLONK) for anonymous governance votes or private bridge claims; no on-chain nullifier table maintained
- Same proof can be submitted multiple times; each submission counts as a valid vote or valid claim
- Nullifier derived from the ZK proof is not stored and checked before accepting each proof

**Detection Heuristics**

- Find the ZK proof verification call; check whether the function also reads a nullifier from the proof and verifies it is not already in a `Table<vector<u8>, bool>` or equivalent
- Verify: `assert!(!table::contains(&nullifiers, proof.nullifier), ERROR_PROOF_REPLAYED)` before accepting, and `table::add(&mut nullifiers, proof.nullifier, true)` after
- Check the nullifier derivation: it should be determined by the private input (secret key, deposit note) and not by any public input that the submitter controls
- Verify the nullifier table is a shared object (or stored in a globally accessible config) not an owned object that could be reset by its holder

**False Positives**

- Nullifier table maintained and checked on every proof acceptance; proof replay returns a specific error code
- Protocol uses a commitment-based scheme where each commitment can only be consumed once; nullifier is implicit in the commitment structure
