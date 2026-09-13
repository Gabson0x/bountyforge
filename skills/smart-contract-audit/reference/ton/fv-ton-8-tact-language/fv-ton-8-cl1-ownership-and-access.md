# FV-TON-8-CL1 Ownership and Access in Tact

## TLDR

Tact's `Ownable` trait provides ownership infrastructure, but authorization is opt-in per handler. Any `receive()` handler that performs privileged state changes without calling `self.requireOwner()` is accessible to any sender.

## Detection Heuristics

**Missing requireOwner on admin handlers**
- Tact contract `receive()` handler for ops like parameter updates, withdrawals, or contract configuration does not call `self.requireOwner()` at the start
- Mixed patterns in the same contract: some admin handlers use `self.requireOwner()`, others do not - inconsistency is the vulnerability

**require() polarity errors**
- `require(condition, "error message")` used where the condition being true should cause rejection - same polarity error as `throw_unless` vs `throw_if` in FunC
- Complex boolean expressions in `require` that invert the intended check

**Ownership not transferred or not two-step**
- No `transfer_ownership()` or equivalent in the Tact contract - admin key loss is unrecoverable
- Single-step ownership transfer with no pending/confirm state - sending to a wrong address is permanent

## False Positives

- Handler is deliberately permissionless and only reads state or emits a notification - no state modification that requires authorization
- `requireOwner()` implemented in a parent trait or base contract that the audited contract inherits - trace the inheritance chain to confirm it is called
