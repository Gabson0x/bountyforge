# FV-SOL-7-C4 Uninitialized Proxy

## TLDR

Proxy contracts that use `initialize()` instead of constructors for setup can be left in an uninitialized state if the initializer is never called, or can be re-initialized if the initializer lacks a one-time-use guard. Either condition allows an attacker to set critical ownership or configuration variables to their own address.

## Detection Heuristics

**No Zero-Address Check on Implementation Before delegatecall**
- `fallback` forwards calls via `delegatecall` without verifying `implementation != address(0)`
- Proxy deployed with implementation address not yet set, calls silently succeed or misbehave

**initialize() Not Protected Against Replay**
- `initialize` function uses no `initializer` modifier or equivalent initialized flag
- `initialized` flag is stored at a slot that can be overwritten by delegatecall storage collision
- Implementation contract's `initialize` is callable directly (not only through the proxy)

**Implementation Contract Missing disableInitializers in Constructor**
- Implementation constructor does not call `_disableInitializers()`
- Direct calls to the implementation's `initialize` can set an attacker-controlled owner on the implementation itself, enabling delegatecall-based exploits (e.g., selfdestruct via implementation takeover)

**Non-Atomic Proxy Deployment and Initialization**
- Proxy deployed in one transaction, `initialize()` called in a separate transaction
- Gap between deployment and initialization exploitable by front-running

**Re-initialization Possible in Upgrade**
- V2 implementation uses `initializer` modifier instead of `reinitializer(2)`, resetting already-initialized state on upgrade

## False Positives

- `initialize` guarded by OpenZeppelin `Initializable.initializer` modifier and called atomically in the proxy constructor via `data` parameter
- `_disableInitializers()` called in the implementation's constructor preventing direct initialization
- Proxy deployment and initialization are a single atomic transaction (init calldata passed to proxy constructor)
- `reinitializer(N)` used with a correctly incrementing version number for each upgrade
