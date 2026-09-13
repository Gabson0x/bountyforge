# FV-SOL-6-C6 False Contract Existence Assumption

## TLDR

Calling a function on an address that contains no contract code does not revert - the EVM treats it as a successful call returning empty data. When a protocol stores or accepts an external address without verifying it is a deployed contract, calls to that address silently succeed as no-ops, producing incorrect state updates or bypassed logic.

## Detection Heuristics

**Unvalidated Address at Construction or Initialization**
- Constructor assigns `externalContract = _addr` without `require(_addr.code.length > 0)`
- `initialize(address token)` stores `token` without verifying it is a contract
- Admin setter `setTarget(address t)` with no `extcodesize` or `code.length` check

**Interface Cast Without Existence Check**
- `IExternalContract(addr).performAction()` where `addr` is user-supplied or comes from an unvalidated storage variable
- Multicall or batch executor iterates over user-provided addresses without per-entry validation

**Post-Creation Use Without Zero-Address Check**
- `factory.deploy()` result used to call methods without checking the returned address is non-zero and is a contract
- Address loaded from a mapping or array that was never validated at write time

## False Positives

- Address validated at storage time with `require(addr.code.length > 0)` before assignment
- Address is a compile-time constant referencing a known deployed contract
- Address constrained to a whitelist where all entries were verified to be contracts at onboarding time
- EIP-1167 minimal proxy: zero-code check is not applicable because the proxy is deployed atomically in the same call
