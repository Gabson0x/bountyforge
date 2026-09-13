# FV-ANC-5-CL11 CPI to Upgradeable Program Without Version Pin

## TLDR

Calling an upgradeable program via CPI exposes the caller to logic changes introduced by the program's upgrade authority. If the calling protocol does not pin the expected program binary hash or validate the upgrade slot, an upgrade to the dependency program can silently change the semantics of the CPI, introduce new account requirements, etc. - without the calling protocol's audit surface being re-evaluated.

## Detection Heuristics

**CPI Target is an Upgradeable BPF Program**
- CPI target's program data account exists and has an upgrade authority that is not `None`
- Program does not load and compare the program data account's `last_deployed_slot` or data hash against a stored expected value
- Protocol documentation does not identify the exact version or commit hash of the external program being integrated

**No Governance Gate on Dependency Upgrade**
- A community-governed or team-controlled program is used as a CPI dependency without a protocol-level check that the program's behavior matches an audited version
- Upgrade authority for the CPI dependency is a multisig or DAO that can act without the calling protocol's consent

**Missing Executable Check at Instruction**
- Program account passed as a CPI target is not checked to be executable at the time of the call
- CPI target account's program data address is not derived and read to verify upgrade authority status

## False Positives

- CPI target's upgrade authority is set to `None` (immutable); the program binary is permanently frozen and cannot be changed
- Calling program explicitly loads the program data account and asserts its hash or last_deployed_slot matches a stored expected value before executing the CPI
