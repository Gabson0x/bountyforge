# FV-TON-6-CL1 set_code and State Migration

## TLDR

`set_code()` takes effect only for subsequent transactions, not the current one. Code upgrades without a matching storage migration leave the new code reading old data in the wrong format - silently corrupting balances, access control, and configuration.

## Detection Heuristics

**Logic after set_code expecting new code**
- Code placed after `set_code()` in the same transaction assumes the new logic is active - the current transaction continues executing the old code through to completion
- Initialization steps intended for the new contract version run under old code semantics

**Missing storage migration**
- `set_code()` without a corresponding `set_data()` that converts the storage layout to the format expected by the new code
- New code adds a field or changes field ordering but old data remains in storage - new code reads fields from wrong offsets, producing incorrect values
- No `version` field in storage to allow the new code to detect format and migrate on first run

**Upgrade without authorization or timelock**
- `set_code()` reachable without admin/owner `equal_slices` check
- No governance requirement or multi-sig for upgrades
- Upgrade executes immediately with no delay for users to review and optionally exit

## False Positives

- Upgrade mechanism intentionally designed as two-step: first transaction sets new code, second transaction (under new code) performs migration - verify the migration step is implemented and cannot be skipped
- Storage layout is identical between old and new code; the only changes are logic - confirm this by comparing all `load_*` / `store_*` sequences in both versions
