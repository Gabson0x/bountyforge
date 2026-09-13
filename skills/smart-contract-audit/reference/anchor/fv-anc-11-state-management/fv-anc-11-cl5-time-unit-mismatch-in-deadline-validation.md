# FV-ANC-11-CL5 Time Unit Mismatch in Deadline Validation

## TLDR

Solana's `Clock` sysvar provides both `unix_timestamp` (seconds since Unix epoch) and `slot` (current slot number). Mixing these two units in deadline or expiry comparisons produces incorrect results: a value stored in seconds interpreted as a slot number, or vice versa, can make a deadline that should expire in one hour appear to expire in days, or vice versa.

## Detection Heuristics

**Mixed Unit Comparison**
- Protocol stores a deadline or expiry as `Clock.slot` but compares it against `Clock.unix_timestamp` in a later instruction, or vice versa
- Expiry field not labeled with its unit in the account struct comment or field name; auditor must trace all write sites to determine whether seconds or slots were intended
- Cooldown or lock duration specified in seconds in the protocol documentation but stored by assigning `Clock.slot + duration_seconds`, producing a value in slots not seconds

**Slot Duration Assumptions**
- Protocol assumes a fixed slot duration (e.g., 400ms per slot) to convert between seconds and slots; actual slot duration varies and the assumption causes drift over time
- Lock duration computation: `current_slot + (lock_seconds / 0.4)` uses hardcoded slot duration that may be inaccurate, making locks shorter or longer than intended

**Cross-Instruction Unit Inconsistency**
- One instruction writes `last_updated_slot = Clock.unix_timestamp` (wrong unit) while another instruction reads `elapsed = Clock.slot - last_updated_slot`, producing nonsensical elapsed time
- Config parameter for timelock duration accepted from user input without validation of whether it is denominated in slots or seconds

## False Positives

- Protocol uses only one time source consistently throughout all instructions; either always `unix_timestamp` or always `slot`, never mixed
- Field names and struct comments explicitly document the unit (`expiry_slot`, `expiry_unix_ts`), and all comparison sites use the matching Clock field
