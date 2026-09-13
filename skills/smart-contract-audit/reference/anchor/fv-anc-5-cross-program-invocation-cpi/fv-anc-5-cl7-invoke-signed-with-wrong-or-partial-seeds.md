# FV-ANC-5-CL7 invoke_signed with Wrong or Partial Seeds

## TLDR

If the seeds array passed to `invoke_signed` does not exactly match the seeds used to derive the PDA that is expected to sign, the call will fail or sign under the wrong identity. More critically, when multiple seed combinations can resolve to valid program addresses, using an incorrect subset can authorize operations under an unintended signer identity, bypassing intended access controls.

## Detection Heuristics

**Seeds Mismatch Between Derivation and Signing**
- Seeds list in `invoke_signed` call differs from seeds used in the corresponding `Pubkey::find_program_address` or `Pubkey::create_program_address` call
- `bump` seed omitted from the `invoke_signed` seeds while the PDA derivation included it, or vice versa
- Seed values sourced from user-supplied accounts without validation used in the signing call

**Incomplete Seed Validation**
- Program dynamically constructs the seeds array at runtime from account fields without asserting the resulting address matches the expected PDA key
- Seeds array passed as a slice reference where individual seed byte arrays come from attacker-controlled instruction data
- No `Pubkey::create_program_address(seeds, program_id) == expected_pda` assertion before the invoke_signed call

**Shared Seed Prefix Ambiguity**
- Multiple PDA types share a seed prefix, and the wrong type can be used as a signer because the seeds are checked by inclusion not exact match
- Bump stored in an account field can be manipulated to produce a different valid PDA address

## False Positives

- Seeds are compile-time constant byte slices that are identical in both derivation and signing call sites; compiler ensures they cannot diverge
- Program verifies the derived address from seeds matches the account key before using it in invoke_signed
