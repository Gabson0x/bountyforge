# FV-TON-2-CL1 recv_external Accept Message Ordering

## TLDR

Calling `accept_message()` before validating the external message signature and sequence number lets attackers drain the contract's TON balance by flooding it with invalid external messages - each accepted call charges gas from the contract.

## Detection Heuristics

**accept_message before validation**
- `accept_message()` appears as the first or near-first statement in `recv_external`, before any `check_signature()` or `throw_unless(seqno == stored_seqno)` call
- Sequence: `accept_message()` → parse body → validate → use; the safe sequence is: parse → validate → `accept_message()` → execute

**Unconditional acceptance**
- `recv_external` that calls `accept_message()` on every message regardless of content or signature
- No signature variable or public key loaded from storage - validation is entirely absent

**Expensive computation before acceptance gate**
- Even if `accept_message()` is after some code, if that code involves expensive cell operations (large dictionary reads, recursive unpacking) before the validation throw, the gas cost is still charged on failure

## False Positives

- Contract intentionally accepts external messages without signature (e.g., a permissionless trigger) and the only effect is an idempotent state change with no fund movement - document the design intent clearly
- `accept_message()` placed before a computationally trivial check (single integer comparison) where the gas exposure is negligible by design
