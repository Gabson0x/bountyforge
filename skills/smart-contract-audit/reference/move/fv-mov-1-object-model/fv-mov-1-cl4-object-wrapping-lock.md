# FV-MOV-1-CL4: Object Wrapping Permanent Lock

## TLDR

A contract wraps a user-owned object inside its own struct (or dynamic field) and provides no guaranteed path to unwrap it. Once wrapped, the inner object loses its independent identity - it cannot be transferred, used, or accessed until explicitly unwrapped by the wrapping contract. If the wrapping contract is malicious or has a bug, the inner object is permanently inaccessible.

## Detection Heuristics

- Identify every function that accepts a user object and stores it inside a struct field or dynamic field owned by the protocol
- For each such wrapping function, verify a corresponding `unwrap`, `extract`, or `return_object` function exists and is accessible by the original owner
- Third-party contracts that accept user objects (marketplaces, staking contracts, escrow) are the highest-risk callsites - verify they expose an unconditional exit path
- Check whether the unwrap function has a precondition that could be made permanently unsatisfiable (e.g., requires a counter to reach a value that is only incremented externally)
- Dynamic object fields preserve child object IDs - search for `dynamic_object_field::add` on sensitive objects

## False Positives

- Wrapping is temporary and the protocol guarantees an unwrap path via an unconditional function callable by the original owner
- Object is intentionally locked (e.g., staked, escrowed) with clear unlock conditions that are fully within the owner's control
- Protocol is audited and the wrapping is a standard, documented design pattern
