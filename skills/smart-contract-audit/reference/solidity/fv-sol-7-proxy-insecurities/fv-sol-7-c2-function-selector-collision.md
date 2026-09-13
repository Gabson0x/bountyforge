# FV-SOL-7-C2 Function Selector Collision

## TLDR

Function selectors are the first four bytes of the keccak256 hash of a function signature. When a proxy contract exposes public functions whose selectors match functions in the implementation, the proxy intercepts and handles those calls itself rather than delegating them, causing silent misbehavior or unauthorized access to proxy-level operations.

## Detection Heuristics

**Public Functions on Proxy Contract**
- Proxy contract defines `public` or `external` functions beyond the fallback and constructor
- Any proxy function selector can be brute-forced or accidentally matched by an implementation function

**Upgrade or Admin Functions Exposed as Public**
- `setImplementation`, `upgradeTo`, or admin transfer functions are `public` instead of `internal` or protected behind a dedicated admin-only path
- Callers targeting the implementation can accidentally trigger proxy-level state changes

**No Selector Isolation Between Proxy and Implementation**
- Proxy and implementation compiled without a tool (e.g., OZ upgrades plugin) that checks for selector collisions at build time
- Implementation ABI not compared against proxy ABI for four-byte collisions before deployment

**Transparent Proxy Pattern Not Applied**
- Proxy does not distinguish between admin callers (routed to proxy functions) and non-admin callers (routed to implementation)
- All callers share the same routing logic, making selector collisions exploitable by any address

## False Positives

- Transparent proxy pattern where admin calls are routed to proxy functions and all other callers are unconditionally forwarded via fallback
- UUPS pattern where upgrade logic lives in the implementation (no public proxy functions that can collide)
- Selector collision checks enforced in CI via the OpenZeppelin upgrades plugin or equivalent static analysis
- Proxy exposes only `fallback` and `receive`, with all admin operations gated through a separate `ProxyAdmin` contract
