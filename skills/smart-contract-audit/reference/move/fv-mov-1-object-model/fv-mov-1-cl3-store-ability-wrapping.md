# FV-MOV-1-CL3: Store Ability Enables Unauthorized Wrapping

## TLDR

A sensitive object (AdminCap, TreasuryCap, UpgradeCap) granted the `store` ability can be wrapped inside any other object and transferred out of the protocol's visibility. The attacker wraps the capability into a custom container and transfers it to an address they control, bypassing transfer policies.

## Detection Heuristics

- Search for `struct AdminCap has store`, `struct TreasuryCap has store`, or any capability-type struct with `store`
- `store` without `key` means the object can only exist inside another object - it cannot be transferred directly, but it can be wrapped and the wrapper can be transferred
- Trace whether any public function returns or hands off the capability object to a caller-controlled destination
- Check whether transfer policies (`TransferPolicy`) are configured on the type; if `store` is present but no transfer policy is enforced, the capability can leak

## False Positives

- `store` is required for storing the capability in a dynamic field within the same protocol's objects, with access gated by internal checks
- Transfer policy enforces correct handling for any object that leaves the module
- Object designed to be storable by protocol design (e.g., delegated capability with intentional transfer path)
