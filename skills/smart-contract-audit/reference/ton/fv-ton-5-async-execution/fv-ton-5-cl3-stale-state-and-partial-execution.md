# FV-TON-5-CL3 Stale State and Partial Execution

## TLDR

In multi-message operations, each sent message creates a separate committed transaction. If any message in the chain fails (bounces or runs out of gas), prior state changes are already committed and require explicit rollback via bounce handling - silence means permanent inconsistency.

## Detection Heuristics

**State committed before multi-message chain completes**
- `set_data()` called after the first successful step in a multi-step operation - if subsequent messages in the chain fail and bounce handlers are absent, the state reflects a partial completion
- Example: debit sender → send credit message to receiver → if credit bounces without handler, sender is debited with no credit issued

**Callback reads cached pre-send state**
- Callback or bounce handler uses local variables captured at the time of the original send rather than re-reading from c4 - if another message modified storage between the send and the callback, the handler operates on stale data
- `get_data()` not called at the start of the bounce handler

**throw after send**
- Developer expects a `throw` after `send_raw_message` to cancel the send - in TVM, a throw during the compute phase reverts the action list (messages queued) along with c4, but this only applies within the current transaction; messages dispatched by already-completed transactions are irreversible
- Relying on throw-based rollback in multi-transaction flows

**Dangling storage references**
- `set_data()` called, then the old slice from before `set_data()` is read again - the old slice is stale and does not reflect the saved state

## False Positives

- Every outgoing message in the chain has a corresponding bounce handler that fully reverts the state change associated with that message
- Partial execution is an accepted protocol state (idempotent operation) and the system self-heals on retry
