# FV-MOV-2-CL2: Capability Created Outside init / Missing OTW

## TLDR

Capability objects (`AdminCap`, `TreasuryCap`) should be created only once during module initialization (`init`). Creating them in any other function, without requiring an existing capability, allows any caller to mint new admin credentials. Similarly, coins created without the one-time witness (OTW) pattern allow external modules to create duplicate `TreasuryCap` instances.

## Detection Heuristics

- Search for `AdminCap { }` or `TreasuryCap` struct constructions outside of `fun init()`
- For coin types, verify `coin::create_currency` is called with a one-time witness (the witness type name matches the module name in all caps, e.g., `MYTOKEN`)
- Check whether `sui::types::is_one_time_witness` is validated before minting
- Capability construction that requires no existing capability is always a finding when outside `init`
- Verify `init` function signature accepts `otw: MODULENAME` as first parameter for coin modules

## False Positives

- Capability creation function requires an existing valid capability as authorization
- Function is `public(package)` with gated access
- OTW validation present via `assert!(sui::types::is_one_time_witness(&witness))`
