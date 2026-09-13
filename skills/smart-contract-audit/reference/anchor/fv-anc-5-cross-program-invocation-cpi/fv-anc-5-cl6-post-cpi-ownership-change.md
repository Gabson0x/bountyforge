# FV-ANC-5-CL6 Post-CPI Ownership Change

## TLDR

A callee program can call `assign` on any account it is authorized to write, changing that account's owner to an arbitrary program. If the caller does not re-verify account ownership after the CPI, it may continue operating on an account now owned by an attacker-controlled program.

## Detection Heuristics

**No Ownership Re-Verification After CPI**
- `ctx.accounts.target.owner` not checked after `invoke` or `invoke_signed` completes
- Account ownership assumed to be unchanged after CPI to an unaudited or user-supplied program
- Fields read or mutations performed on an account after a CPI without confirming `account.owner == &expected_program_id`

**Writable Accounts Passed to Unknown Programs**
- `AccountInfo` passed as writable to a CPI where the target program is not a well-known audited program, creating a surface for ownership reassignment
- Dynamic program ID used as CPI target combined with writable accounts that the current program later relies on

**No Post-CPI Invariant Checks**
- Instruction performs a series of operations after a CPI without any validation that account state (owner, data, lamports) is within expected bounds

## False Positives

- CPI target is a well-known program (SPL Token, System Program, Metaplex) that does not call `assign` as part of its instruction
- Account ownership is enforced at the Anchor deserialization level on the next instruction, making within-instruction re-check redundant only if no further reads occur after the CPI in the same instruction
