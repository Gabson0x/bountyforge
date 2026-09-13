# FV-ANC-4-CL2 PDA Seed Concatenation Collision

## TLDR

When multiple variable-length byte slices are passed as PDA seeds without length disambiguation, different combinations of inputs can produce the same raw seed bytes and therefore the same PDA address. An attacker can craft inputs that collide with a legitimate account's PDA.

## Detection Heuristics

**Adjacent Variable-Length Seeds Without Separators**
- `Pubkey::find_program_address(&[prefix.as_bytes(), suffix.as_bytes()], program_id)` where both seeds are variable-length strings or byte slices
- Two or more `&str` or `Vec<u8>` seeds concatenated as adjacent slices without length prefixes or fixed-length encoding

**String Seeds Derived From User Input**
- Seeds include user-provided names, labels, or identifiers that are not fixed-length, creating collision opportunities between different user inputs

**Anchor seeds Constraint With Dynamic Slices**
- `#[account(seeds = [user_input_a.as_ref(), user_input_b.as_ref()], bump)]` where both inputs are variable-length

## False Positives

- All seed components are fixed-length (e.g., `Pubkey` references at 32 bytes, `u64` encoded as 8 bytes), making concatenation unambiguous
- Seeds use a constant string separator between variable-length components that cannot appear in the values themselves
- Only a single variable-length seed component is used alongside fixed-length components
