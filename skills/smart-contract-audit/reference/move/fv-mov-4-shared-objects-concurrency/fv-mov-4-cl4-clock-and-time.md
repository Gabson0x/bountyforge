# FV-MOV-4-CL4: Clock Usage and Time Unit Errors

## TLDR

Sui provides reliable on-chain time via `clock::timestamp_ms(&clock)`, which returns time in milliseconds. Common failures: (1) `Clock` not used at all; (2) time constants mixed between milliseconds and seconds; (3) no deadline parameter on time-sensitive operations. These result in locks that are instantly expired or last years, and operations that execute at stale conditions.

## Detection Heuristics

- Search for hardcoded time comparisons not using `clock::timestamp_ms` - these use no reliable on-chain time source
- Find all time constants (lock durations, staleness thresholds, vesting periods) and verify they end with `_MS` and represent milliseconds
- A constant like `one_day = 86400` (without `_MS`) compared against `clock::timestamp_ms` makes the lock 86 seconds; `one_day = 0` (SuiPad finding) makes it instant
- Check every swap, deposit, and withdrawal function for a `deadline_ms: u64` parameter and `assert!(clock::timestamp_ms(&clock) <= deadline_ms)`
- Verify `Clock` is passed as `&Clock` (shared object at address `0x6`) - not created locally

## False Positives

- Constants documented as milliseconds with explicit `_MS` suffix and correct values
- Deadline parameter present and enforced on all time-sensitive functions
- No time-dependent logic in the contract
