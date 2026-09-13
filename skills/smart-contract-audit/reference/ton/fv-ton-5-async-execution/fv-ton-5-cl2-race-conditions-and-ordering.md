# FV-TON-5-CL2 Race Conditions and Message Ordering

## TLDR

Message ordering between different source contracts is not guaranteed on TON. Only messages from the same sender to the same receiver maintain order via logical time - cross-contract flows can interleave unpredictably, causing race conditions on shared mutable state.

## Detection Heuristics

**Shared state modified by independent flows**
- Two users can simultaneously send messages that both read and write the same contract state (e.g., a shared pool balance or auction slot) - whichever arrives second may overwrite the first without seeing its update
- First-come-first-served logic (claim a slot, win an auction) with no locking mechanism

**Cross-contract ordering assumptions**
- Contract expects message from A to arrive before message from B (based on initiation order), but both are from different senders to the same contract - order is validator-dependent
- Setup or configuration message assumed to arrive before operational messages in multi-contract initialization sequences

**Balance-check race**
- Two concurrent withdrawal requests both pass the balance check before either deducts - double-spend pattern via race condition on the same balance field
- No "pending withdrawal" entry or lock to prevent concurrent claims

**raw balance usage**
- `my_balance` or raw contract balance (manipulable by any sender) used for business logic - attacker sends TON directly to inflate balance before triggering a balance-dependent path

## False Positives

- All writes to the shared state go through a single serialized queue or use a lock that is set and checked atomically in the same message handler
- The state is per-user (keyed by sender address) and no two users can affect each other's entries
