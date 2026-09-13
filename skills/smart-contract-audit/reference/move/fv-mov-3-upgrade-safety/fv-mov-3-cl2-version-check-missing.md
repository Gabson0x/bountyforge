# FV-MOV-3-CL2: Missing Version Check on Shared Objects

## TLDR

After a package upgrade, old transactions may still call functions from the pre-upgrade package against existing shared objects. Without a `version` field and a per-function version assertion, old and new code can interleave, producing incompatible state transitions.

## Detection Heuristics

- Check every shared object struct for a `version: u64` field
- Check every public function that mutates a shared object for `assert!(obj.version == CURRENT_VERSION, EVersionMismatch)`
- Search for the `CURRENT_VERSION` constant and verify it is incremented in each upgrade
- Verify a migration function exists that atomically increments the version field after upgrading all objects
- Missing version checks combined with struct field additions is a compound finding

## False Positives

- Package is immutable (no future upgrades possible); version checks are unnecessary
- Protocol design guarantees that only one version of code will ever touch the object (e.g., single-use objects destroyed after first use)
- Version field present and checked in a shared helper called by all public functions
