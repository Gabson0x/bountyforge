# FV-VYP-4-C1 Unchecked External Call Returns

## TLDR

Vyper's `raw_call` returns a `bool` success flag and optional `Bytes` return data. When `revert_on_failure=False` is passed or when the return value is discarded, a failed external call silently continues execution. Unlike Solidity's low-level `.call()`, Vyper callers may not realize that `raw_call` with `revert_on_failure=False` requires explicit success validation.

## Detection Heuristics

**`raw_call` result not captured or not asserted**
- `raw_call(target, data, ...)` called as a statement with no assignment: `raw_call(target, b"", value=amount)` with no `success: bool =` prefix and default `revert_on_failure=True` assumed but not verified
- `success: bool = raw_call(..., revert_on_failure=False)` present but `success` never checked afterward before continuing execution or emitting state changes
- `raw_call` inside a loop where one failing iteration does not halt the loop and remaining iterations proceed with incorrect accounting

**Interface calls to ERC-20 tokens that return `bool`**
- `IERC20(token).transfer(to, amount)` return value not captured, relying on revert behavior that non-standard tokens (e.g., USDT) do not implement
- `IERC20(token).transferFrom(...)` called without checking the returned `bool`, silently failing on tokens that return `False` instead of reverting

**Batch dispatch with no per-call failure handling**
- A `for` loop over `DynArray[address, N]` calling `raw_call` on each entry where a failed call does not revert the entire batch and accounting proceeds as if all succeeded
- Silent failure in one leg of a multi-recipient distribution leaves the contract's internal balance accounting inconsistent with actual ETH transferred

## False Positives

- `raw_call` where `revert_on_failure=True` (the default) is used, causing the call to revert the entire transaction on failure
- Calls to `raw_call` used purely for side-effect notification (e.g., pinging a logging contract) where the contract's own state does not depend on the callee's success
- ERC-20 interfaces where the token is a known, audited implementation that always reverts on failure rather than returning `False`