# FV-MOV-2-CL1: Missing Capability Check on Privileged Function

## TLDR

A function that performs admin or privileged operations (withdraw, mint, pause, config update) does not require a capability object parameter. Any user can call the function and perform admin operations without restriction.

## Detection Heuristics

- Enumerate all functions that touch sensitive state: treasury, admin config, pause flags, supply, upgrade logic
- For each such function, check whether its signature includes a `_: &AdminCap`, `cap: &TreasuryCap`, or equivalent capability reference
- A function with only `ctx: &mut TxContext` and no capability parameter that modifies privileged state is a finding
- Address-based checks (`assert!(ctx.sender() == stored_admin)`) are weaker but acceptable as a secondary defense; they are insufficient if the admin address is hardcoded or not stored mutably
- Pay attention to functions in `entry` visibility - these are callable directly from a transaction by any user

## False Positives

- Function is `public(package)` and not callable from outside the package
- Address-based check present with the address stored in a mutable config object (not hardcoded)
- Function performs no privileged state change - it only reads or emits events
