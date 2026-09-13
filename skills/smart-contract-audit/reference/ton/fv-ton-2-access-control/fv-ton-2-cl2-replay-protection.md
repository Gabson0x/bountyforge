# FV-TON-2-CL2 Replay Protection

## TLDR

External message handlers without sequence number validation, or with seqno incremented after execution rather than before, allow valid signed messages to be replayed indefinitely - re-executing transfers, withdrawals, or any privileged action.

## Detection Heuristics

**Missing seqno check**
- `recv_external` does not load or compare `seqno` from the message body against the stored value
- No `throw_unless(error::bad_seqno, msg_seqno == stored_seqno)` call
- Sequence number stored in c4 but not loaded via `load_data()` before use

**Seqno incremented after execution**
- Seqno updated and saved via `set_data()` at the end of the handler - if execution throws after the main action but before `set_data()`, the replay window remains open
- Safe pattern: load → validate → `accept_message()` → increment seqno → `set_data()` → execute actions

**Internal message replay**
- Internal messages that trigger privileged one-time actions (e.g., claim, initialize) have no idempotency mechanism - no nonce, no "already processed" flag in a dictionary
- Same signed external message deliverable across restarts or forks if valid_until is not checked

## False Positives

- Contract is a stateless relay that processes every incoming message identically - replay is intentional by design
- Seqno check present in an inlined helper function; follow the call to confirm it executes before `accept_message()`
