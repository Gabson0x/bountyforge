---
name: code-sleuth
description: Analyze EVM smart contracts for storage-safety vulnerabilities that can cause persistent state updates to be lost, overwritten, misdirected, or to collide across proxy or upgrade boundaries.
---


Focus on bugs involving:

- memory vs storage confusion
- lost writes (state mutated in memory but never persisted)
- arbitrary or attacker-influenced storage slot writes
- storage collisions across proxy/upgrade layouts
- other storage semantics that can corrupt or invalidate state

Only report issues that have a **clear persistence or state integrity impact**.

---

## Applicability gates

Only proceed if BOTH conditions are true:

1. The contract contains **state-mutating logic** intended to update persistent storage (balances, shares, positions, roles, configuration, accounting totals, escrow mappings, arrays of records, etc.).

2. At least one of the following storage-risk signals is present:

- writes to structs, arrays, or mappings
- inline assembly interacting with storage (`sstore`, `sload`)
- manual or unstructured storage slots (`bytes32` slot constants, StorageSlot libraries)
- proxy, upgradeable, diamond, or delegatecall-based architecture

If these gates are not satisfied, do not force findings.

---

## Workflow

### 1) Inventory storage and storage writers

Map the contract’s persistent state surface before looking for bugs.

- Identify key storage variables such as balances, shares, totals, configuration, roles, escrow mappings, or arrays of user positions.
- Enumerate functions that mutate them:
    - external/public non-view functions
    - internal helpers reachable from those functions
    - privileged admin or upgrade paths
- Identify manual slot usage such as:
    - inline assembly `sstore` / `sload`
    - `StorageSlot` libraries
    - `bytes32` slot constants
    - custom slot arithmetic

Use this inventory to anchor later findings to **specific variables and write paths**.

---

### 2) Lost write / memory-versus-storage omission

Look for cases where storage-backed data is copied into a temporary value, modified, but never written back to storage.

Typical pattern:

- A storage value (struct, mapping element, or array entry) is copied into memory or into a value-type variable.
- The temporary variable is mutated.
- The mutation is never persisted back to the original storage location.

Report a finding only if **all** of the following are true:

- A storage-backed value is copied into a non-storage temporary.
- That temporary is mutated (field assignment, push/pop, arithmetic update, etc.).
- On all reachable paths, the mutated value is **not written back** to the original storage location.
- The surrounding logic indicates that persistence was expected.

Indicators that persistence is expected:

- function name suggests an update
- emitted events imply a state change
- later code reads the state assuming it was updated
- callers rely on the update for accounting or permissions

Do not report if:

- the function is clearly `view` or `pure`
- the code intentionally constructs and returns a modified copy
- the variable is actually a storage reference
- the value is written back through a helper function on all paths

---

### 3) Attacker-influenced storage slot writes

Look for cases where **untrusted input affects which storage slot is written**.

This usually occurs in:

- inline assembly
- custom slot arithmetic
- manual mapping key construction
- delegatecall-based modules or registries

Report a finding only if **all** of the following are true:

- attacker-controlled input influences the final storage slot or key used in a write
- the slot or key is not strictly constrained by validation, allowlists, or provenance checks
- the resulting write can corrupt unrelated or sensitive state

Examples of realistic overwrite targets:

- owner or admin variables
- configuration parameters
- balances or accounting mappings
- implementation or proxy slots
- governance roles

Do not report if:

- the slot is a fixed constant used in a standard pattern
- strong access control prevents untrusted writes
- input-derived keys are tightly validated against trusted state

---

### 4) Upgradeable storage collisions and layout hazards

If the contract uses proxy, upgradeable, or diamond architecture, examine storage layout safety.

Look for situations where storage from multiple implementations or facets could overlap.

High-risk signals include:

- upgrade mechanisms such as `upgradeTo`, `diamondCut`, or admin-controlled implementation changes
- inheritance-heavy storage layouts without reserved gaps
- custom slot constants inconsistent with EIP-1967 or other standard patterns
- facets or modules declaring overlapping state without a shared storage struct pattern

Report layout issues carefully:

- If you can demonstrate an **actual collision**, report it as a concrete vulnerability.
- If there is only a credible risk during upgrades, report it as an **upgrade-safety risk**.

Do not report if:

- the contract has no upgrade mechanism
- storage layout follows a standard pattern with reserved gaps and consistent slot usage

---

### 5) Other storage semantics (only when security-relevant)

Look for storage behaviors that can corrupt or desynchronize state.

Examples include:

- deleting mapping or struct entries while leaving auxiliary state inconsistent (index arrays, totals, role flags)
- manual bit packing or bitmap logic that fails to clear or mask stale bits
- uninitialized storage reads used as authorization or accounting signals

Only report issues where the result could cause:

- privilege escalation
- incorrect accounting
- corrupted configuration
- inaccessible funds
- broken protocol invariants
