# FV-ANC-3-CL12 Not Validating a Set Address

## TLDR

When an instruction stores a new address into an account field (e.g., updating a treasury, fee recipient, or authority), failing to validate that address allows arbitrary pubkeys to be set. This can redirect funds, grant privileges to attacker-controlled accounts, or break protocol invariants.

## Detection Heuristics

**Unconstrained Address Update**
- `ctx.accounts.config.treasury = new_address` or similar field assignment without preceding validation of `new_address`
- Address stored from instruction data without checking it is not the System Program, a PDA of the current program, or a known-invalid address

**No Existence or Receivability Check**
- New address not verified to be an initialized account that can receive tokens or lamports
- Fee recipient or authority address updated to a PDA that has no associated token account for the relevant mint

**No Access Control on the Update Instruction**
- Instruction that sets an address does not enforce that only a privileged authority (admin, DAO, multisig) can call it
- Missing `has_one = admin` or equivalent signer constraint on the update instruction context

## False Positives

- New address is derived on-chain from a PDA computation and validated by seeds rather than passed as user input
- Address is constrained to a fixed set of known values enforced by a `constraint` expression
