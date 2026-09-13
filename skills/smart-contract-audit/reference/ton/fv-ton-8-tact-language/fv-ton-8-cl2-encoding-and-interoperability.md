# FV-TON-8-CL2 Tact Encoding and Cross-Language Interoperability

## TLDR

Tact structs and messages serialize to cells using Tact's own encoding conventions. When a Tact contract sends messages to a FunC contract (or vice versa), field widths, layout, and op codes must match exactly - silent mismatches cause incorrect parsing with no error.

## Detection Heuristics

**Op code mismatch between Tact and FunC**
- Tact message type's op code (derived from the message type name hash) does not match the FunC constant used by the receiving contract to dispatch
- Custom op code defined with `@opcode` in Tact does not equal the `const op::*` in the FunC counterpart

**Field width and ordering mismatch**
- Tact `Bool` (1 bit) or `Int` (257 bits default) field widths do not match the `load_uint(N)` / `store_uint(N)` widths expected by the FunC side
- Fields serialized in a different order in Tact structs than the FunC parser reads them
- Tact optional fields (`Int?`) add a 1-bit presence flag - FunC reader that does not skip this flag misaligns all subsequent fields

**Error code incompatibility**
- Tact's `require(condition, "message")` throws with a string-derived code; FunC contracts that catch specific numeric exit codes to determine response type will fail to match
- Cross-contract protocol relies on catching specific error codes to decide whether to retry or abort

## False Positives

- Tact and FunC contracts verified to have matching field layouts by a canonical TL-B schema that both implement against - confirm the schema is up to date with both implementations
