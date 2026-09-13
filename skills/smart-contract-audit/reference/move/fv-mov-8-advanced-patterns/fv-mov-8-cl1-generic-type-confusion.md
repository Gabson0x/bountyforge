# FV-MOV-8-CL1: Generic Type Confusion and Phantom Type Bypass

## TLDR

Unvalidated generic type parameters are the number-one critical vulnerability across real Move audits. An attacker creates a worthless `Coin<FakeUSDC>` and passes it to any function accepting `Coin<T>` without type validation, borrowing real assets against fake collateral. Phantom types on generic capabilities (`RoleCap<T>`) with no concrete type check enable role confusion.

## Detection Heuristics

- Find every function with a generic type parameter `<T>` that handles `Coin<T>`, `Balance<T>`, or any value-bearing type - verify `T` is validated against a stored type identifier or a whitelist
- Safe pattern: pool or vault struct uses `Pool<T>` - the phantom type on the container forces the function to only accept `Coin<T>` for the same `T`; verify this pattern is used consistently
- Search for `type_info::type_of::<T>()` comparisons - verify they compare against a stored expected type, not a hardcoded string that could be bypassed
- For role capabilities `RoleCap<T>` used in access control: verify the function asserts `T` is the expected concrete type, not just any type satisfying the constraint
- Navi Protocol and Econia are named examples - any lending or AMM function accepting generic coins without pool-level phantom type binding is high risk

## False Positives

- Pool/vault struct uses phantom type binding: `Pool<T>` forces all operations to use matching `Coin<T>`
- Explicit type registry: `assert!(type_info::type_of<T>() == stored_type)`
- Function is `public(package)` and only called by trusted internal code with statically verified types
