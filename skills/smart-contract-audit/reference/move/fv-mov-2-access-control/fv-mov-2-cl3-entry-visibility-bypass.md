# FV-MOV-2-CL3: entry Modifier Overrides public(package) Visibility

## TLDR

A function declared `public(package) entry` is intended to be callable only within the package, but the `entry` modifier allows it to be called directly from any transaction. The `entry` keyword overrides the `public(package)` restriction, turning an internal function into public attack surface.

## Detection Heuristics

- Search for `public(package) entry` function declarations across all `.move` files
- For each such function, assess whether it contains privileged operations, admin logic, or internal state manipulation that should not be externally callable
- The correct pattern for a function callable from PTBs but not raw transactions is `public` (not `public(package) entry`)
- The correct pattern for a package-internal function is `public(package)` without `entry`
- Any `public(package) entry` function with sensitive logic is a finding unless there is a documented rationale

## False Positives

- Function performs only read operations with no sensitive state changes
- Function is intentionally both package-restricted and directly callable by transaction (rare, document rationale)
- Modern Sui version where `public(package) entry` semantics have been clarified to not expose externally
