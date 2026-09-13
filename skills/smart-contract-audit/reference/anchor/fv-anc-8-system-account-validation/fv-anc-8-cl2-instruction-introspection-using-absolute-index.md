# FV-ANC-8-CL2 Instruction Introspection Using Absolute Index

## TLDR

Programs that call `load_instruction_at_checked(index, ...)` with a hardcoded or fixed index assume a specific transaction layout. An attacker can prepend additional instructions, shifting the intended instruction to a different position and causing the verification to either fail or point at an unrelated instruction, bypassing the security check or triggering a denial of service.

## Detection Heuristics

**Hardcoded Index in Instruction Sysvar Read**
- `load_instruction_at_checked` or equivalent called with a literal index (e.g., `0`, `1`, `ix_index - 1`) rather than a dynamically discovered index
- Program uses `current_index - 1` to find a preceding instruction without verifying that instruction matches the expected program ID and data
- Index value treated as authoritative without checking the located instruction's program ID

**No Program ID Validation on Located Instruction**
- Instruction loaded by index but program ID of that instruction not compared against an expected constant before trusting its data
- Instruction data parsed from the introspected instruction without verifying it originated from the expected program (e.g., Ed25519 or Secp256k1 native program)
- Error condition when the expected instruction is not at the given index is a generic failure rather than a specific invalid-instruction error

**Attacker Can Prepend Instructions**
- Transaction allows arbitrary number of pre-instructions before the main instruction; no constraint on total instruction count
- Nonce or fee-payment instruction prepended by attacker shifts all subsequent instruction indices by one

## False Positives

- Program iterates all instructions and searches for one from the expected program with the expected discriminator, regardless of position; absolute index is never trusted
- Index is provided as an instruction parameter and the program validates that the instruction at that index has the expected program ID and data prefix
