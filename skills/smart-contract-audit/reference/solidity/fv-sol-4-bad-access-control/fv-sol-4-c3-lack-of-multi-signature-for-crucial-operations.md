# FV-SOL-4-C3 Lack of Multi-Signature for Crucial Operations

## TLDR

When a single address controls a critical operation - such as draining contract funds, upgrading implementation logic, or changing protocol parameters - that address is a single point of failure. Compromise, loss, or coercion of that one key results in irreversible protocol damage with no recourse.

## Detection Heuristics

**Single-Owner Control Over High-Impact Operations**
- `require(msg.sender == owner)` as the sole guard on functions that transfer all funds, pause the protocol, or change fee parameters
- `withdrawAllFunds`, `emergencyDrain`, `transferOwnership`, or `upgradeTo` callable by a single EOA without a timelock or co-signer requirement
- Owner address is an EOA (not a multisig) verified via etherscan or deployment scripts

**Missing Approval Threshold Pattern**
- No multi-step approval mapping (e.g., `approvals[tx]++` + `require(approvals[tx] >= threshold)`)
- No timelock delay before execution of high-impact changes
- No governance vote or quorum check before execution

**Irreversibility Without Safeguards**
- Fund withdrawal sends full balance in a single call with no partial-withdrawal limit
- Upgrade or ownership transfer takes effect immediately with no cancellation window

## False Positives

- Owner address is a deployed Gnosis Safe or other multisig contract
- Operation is protected by a timelock contract requiring a mandatory delay before execution
- Governance module requires on-chain vote with quorum before the privileged call can execute
- Operation is bounded by a small daily limit making catastrophic single-transaction drain impossible
