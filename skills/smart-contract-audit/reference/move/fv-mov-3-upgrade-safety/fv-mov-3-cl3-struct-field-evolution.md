# FV-MOV-3-CL3: Struct Field Evolution Breaks Deserialization

## TLDR

Sui Move enforces forward-compatible struct evolution: fields may only be appended, never reordered or removed. Violating this rule causes existing on-chain objects (created by the old code) to fail deserialization when accessed by the new code.

## Detection Heuristics

- When reviewing an upgrade diff, check whether any struct field was removed, renamed, or reordered
- New fields must be appended at the end; reordering even non-sensitive fields breaks binary layout
- Verify the upgrade's migration function addresses any objects that must be touched before the new code accesses them
- Types with `Option<T>` for new fields are safer than mandatory fields - verify the new field is `Option<T>` or has a safe default

## False Positives

- Fields only appended (never reordered or removed) - this is the only safe pattern
- New fields are optional with documented safe defaults
- No existing on-chain objects of the modified type (brand new struct in the upgrade)
