# FV-SOL-6-C2 Unchecked Transfer Return

## TLDR

Failing to check the return value of `transfer` or `transferFrom` on ERC20 tokens allows silent transfer failures to go undetected. Certain tokens return `false` instead of reverting on failure; ignoring the return value lets execution continue as if the transfer succeeded, leading to incorrect balance accounting or drained protocol value.

## Detection Heuristics

**Discarded Return Value**
- `token.transfer(recipient, amount)` as a bare statement with return value ignored
- `token.transferFrom(from, to, amount)` with no bool capture or require check

**Captured but Unchecked**
- `bool success = token.transfer(...)` where `success` is never evaluated before the function returns
- Return value stored in a local variable that is shadowed or unused

**Missing SafeERC20 Wrapper**
- Raw interface call to `IToken.transfer` or `IERC20.transferFrom` without `SafeERC20` in import list
- Protocol documents USDT or BNB support while using raw `transfer` calls that require a bool return

## False Positives

- `require(token.transfer(...), "failed")` explicitly enforces revert on false return
- `SafeERC20.safeTransfer` or `SafeERC20.safeTransferFrom` used for all token operations
- Token is a known fully-compliant ERC20 that always reverts on failure and the whitelist is enforced in tests
