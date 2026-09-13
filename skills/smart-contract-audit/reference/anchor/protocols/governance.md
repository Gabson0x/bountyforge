# Governance and Authority Management Security Patterns

> Applies to: on-chain governance programs, multisig-controlled protocols, upgrade authority management, DAO voting mechanisms, protocol parameter update mechanisms, admin key rotation, timelock controllers, Squads multisig integrations, veToken governance, any protocol with privileged on-chain authority that controls parameter updates or fund movements

## Protocol Context

Governance and authority management protocols on Solana control the ability to upgrade program binaries, update protocol parameters, pause operations, and move treasury funds. The attack surface is concentrated in the authority transfer, key rotation, and timelock enforcement paths. A single keypair with upgrade authority over a large protocol is a high-value target; the security model must ensure that no single point of failure can compromise protocol integrity. Solana's program upgrade mechanism requires explicit authority transfer and the authority can be set to None for immutability, making the upgrade authority configuration a binary security property that is auditable on-chain.

## Bug Classes

---

### Upgrade Authority Not Protected (ref: fv-anc-13-cl3)

**Protocol-Specific Preconditions**

- Program data account's upgrade authority is a single keypair not protected by multisig or timelock
- Upgrade authority was not transferred to a multisig or set to None after the protocol launched and stabilized
- Protocol documentation claims immutability or strong decentralization but on-chain upgrade authority state contradicts this

**Detection Heuristics**

- Check the program data account's upgrade authority on-chain: `solana program show <program_id>` reveals the authority address
- If authority is not None, verify it is a Squads multisig or governance program, not a single wallet
- Check whether the upgrade authority's governance process includes a mandatory timelock before any upgrade takes effect
- Verify that emergency upgrade paths, if they exist, also require multisig authorization rather than a single key

**False Positives**

- Upgrade authority is explicitly set to None; program is immutable and the finding does not apply
- Authority is a well-audited Squads multisig with a documented threshold, named keyholders who are independent parties, and an enforced timelock

---

### Authority Transfer Without Two-Step Confirmation

**Protocol-Specific Preconditions**

- Authority transfer instruction immediately assigns the new authority in a single transaction without requiring the new authority to accept
- A typo or incorrect address in the authority transfer permanently locks the protocol, as the specified new owner cannot sign to accept
- No two-step pattern (propose -> accept) enforced for any authority-transferring instruction

**Detection Heuristics**

- Find all instructions that write an `authority`, `owner`, `admin`, or `upgrade_authority` field
- Check whether the write is immediate or whether the instruction stores a `pending_authority` that must be claimed by the new authority in a separate transaction
- Verify that the new authority address is validated against a non-zero, non-program-address value before the transfer is committed
- Check for an emergency revoke path that allows the current authority to cancel a pending transfer before it is claimed

**False Positives**

- Two-step transfer enforced: first instruction stores `pending_authority`, second instruction requires signature of the pending authority to finalize
- Protocol's authority is a governance program where new authority assignments go through a voting period, providing an implicit multi-party confirmation

---

### Governance Timelock Not Enforced

**Protocol-Specific Preconditions**

- Protocol claims to enforce a timelock between proposal and execution, but the timelock duration is stored in a mutable config that the admin can reduce to zero before executing a proposal
- Timelock check compares against a relative delay from proposal creation but the proposal timestamp is writable and can be manipulated
- Timelock can be bypassed by a two-step: create proposal with future timestamp, then update the proposal timestamp to the past before execution

**Detection Heuristics**

- Identify the timelock enforcement path: find where `current_time - proposal_created_at >= timelock_duration` is checked
- Verify that `proposal_created_at` is written only once at proposal creation and cannot be modified by subsequent instructions
- Check whether `timelock_duration` in the config can be set to 0 by the admin; if so, verify this is documented and the governance process requires a separate timelock for config updates
- Verify that the execution path cannot be reached through any alternative instruction that bypasses the timelock check

**False Positives**

- Proposal creation timestamp is set from `Clock.unix_timestamp` at creation and is immutable; no instruction allows modifying it after creation
- Timelock duration is a program constant rather than a mutable config field; it cannot be reduced without a program upgrade

---

### Missing Governance for Protocol Parameter Updates

**Protocol-Specific Preconditions**

- Protocol parameters (fee rates, liquidation thresholds, supported mints, oracle addresses) are updatable by a single admin without governance or timelock
- Parameter update instructions lack input validation allowing admin to set economically harmful values (0% fee making the protocol insolvent, 100% collateral factor making all positions liquidatable)
- No event emitted or log recorded when parameters are changed, making changes invisible to monitoring systems

**Detection Heuristics**

- Find all instructions that write to protocol config or parameter accounts; check who can call them and what validation is applied to the new values
- Verify that critical parameters (liquidation threshold, fee rates, oracle addresses) have bounded valid ranges enforced by `require!` statements
- Check whether parameter update instructions emit an event or log that off-chain monitoring can detect
- Identify whether any combination of parameter values can be set that would immediately harm existing users (e.g., setting a collateral factor that makes all positions liquidatable)

**False Positives**

- Parameter updates require a multisig or DAO vote with a timelock; admin cannot unilaterally change critical parameters
- All parameter write instructions include range validation bounds that prevent values outside a documented safe range

---

### Emergency Pause Mechanism Centralization

**Protocol-Specific Preconditions**

- Pause authority is a single keypair with no multisig requirement, enabling censorship or targeted freezing of specific user accounts
- Pause mechanism does not distinguish between user operations (deposit, withdraw) and protocol operations (liquidation, settlement); pausing user access also blocks protocol health maintenance
- No defined process or on-chain constraint for when and how the pause is lifted; indefinite pause is possible

**Detection Heuristics**

- Identify the pause authority account and verify whether it requires a multisig signature
- Check whether the pause flag differentiates between classes of operations; a health-critical operation like liquidation should not be pausable by the same mechanism as deposits
- Verify whether there is a maximum pause duration enforced on-chain that would auto-resume the protocol after a bounded period
- Check whether pausing can be used selectively against individual user accounts or only globally

**False Positives**

- Pause authority requires Squads multisig authorization with documented threshold
- Liquidations and other protocol health operations are explicitly excluded from the pause mechanism via separate access control checks
