# FV-MOV-2-CL4: Caller Address Accepted as Parameter

## TLDR

A function accepts a `sender: address` parameter to determine the caller's identity, rather than deriving it from `tx_context::sender(ctx)`. Any caller can spoof any address by passing a victim's address, enabling them to perform operations on the victim's behalf.

## Detection Heuristics

- Search for function signatures containing `sender: address` or `caller: address` as user-supplied input
- Trace whether the address parameter is used for ownership checks, balance lookups, object transfers, or reward claims
- The safe pattern is always `let sender = tx_context::sender(ctx)` - address derived from the transaction, not passed in
- Look for `assert!(param_addr == tx_context::sender(ctx))` - this check would fix the issue, but its absence is a finding
- Pay special attention to NFT transfer, reward claim, and delegation functions where impersonation has direct economic impact

## False Positives

- Address parameter is only used for destination/recipient (not as a caller identity claim) and the function does not check ownership against it
- Address parameter validated against `tx_context::sender(ctx)` immediately upon function entry
- Function is an internal helper only callable from package functions that have already validated caller identity
