# FV-TON-8-CL3 Tact Map and Init Patterns

## TLDR

Tact `map<K,V>` types are unbounded by default and lack built-in size tracking. The `init()` function can be replayed post-deployment if no initialized guard is present, overwriting all contract state including the owner.

## Detection Heuristics

**Unbounded map growth**
- `map<Address, Int>` or similar type accumulates entries on every user interaction without a maximum size check
- Iteration over the map (`foreach` or similar) in a single transaction without a per-call iteration limit - gas exhaustion when the map grows large enough
- No separate counter variable tracking map size to enforce a cap

**Missing initialized guard in init()**
- Tact `init()` function callable again after deployment because no `is_initialized` field is stored and checked at the start of `init()`
- Re-calling `init()` resets `owner`, `balance`, or other critical state to attacker-supplied values
- Contract deployed via factory but `init()` can still be triggered by sending a message with the corresponding payload

**receive() fallback over-reach**
- Tact's empty `receive()` fallback handler (processes plain TON transfers) contains state-modifying logic - any TON transfer triggers it, including dust deposits from attackers
- Missing `receive()` causes all plain TON transfers to be rejected, breaking expected deposit flows

## False Positives

- Map is used for a bounded set (e.g., a fixed number of supported tokens) and a size check enforces the cap at insertion time
- `init()` is protected by a deployer check: `require(sender() == deployer_address, "already initialized")` where `deployer_address` is set at first and only first execution
