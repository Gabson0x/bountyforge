# FV-TON-5-CL1 Async Reentrancy

## TLDR

TON's actor model enables reentrancy through message ordering rather than call stacks: a contract sends a message and another message arrives before the callback, reading and modifying state between the send and the response - each as separate committed transactions.

## Detection Heuristics

**No operation-in-progress lock**
- Contract updates state, sends a message, and expects a callback, but no "processing" or "locked" flag prevents other messages from modifying the same state while awaiting the response
- Pattern: user A calls → state updated → message sent to B → user B (or A again) calls before callback arrives → state modified again → callback processes stale expectations

**Callback handler reads pre-send state**
- Callback or bounce handler re-reads storage but applies logic based on values captured before the original send - those values may have changed between the send and the callback
- No re-validation of preconditions (e.g., balance still sufficient, position still open) in the callback path

**Multi-message operation without sequence enforcement**
- Contract initiates a chain A→B→C and acts on A's state assumption, but B or C can be overtaken by other messages targeting A's state

## False Positives

- Contract uses a per-user processing flag stored in a dictionary and only one operation per user can be in flight at a time - verify the flag is set before the send and cleared in both success and bounce paths
- The state being protected cannot be modified by any other message (e.g., it is keyed to the in-flight operation ID) - trace all write paths to confirm mutual exclusion
