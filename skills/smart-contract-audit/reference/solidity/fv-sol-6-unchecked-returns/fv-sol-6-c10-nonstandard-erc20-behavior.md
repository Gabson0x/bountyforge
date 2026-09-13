# FV-SOL-6-C10 Non-Standard ERC20 Behavior

## TLDR

Several widely-used tokens deviate from the ERC20 spec in ways that break standard protocol integration:

- **Missing return value** (USDT, BNB): `transfer()`/`transferFrom()` return nothing instead of `bool`. Calling `require(token.transfer(...))` reverts.
- **Non-zero to non-zero approve revert** (USDT): `approve(spender, amount)` reverts if current allowance is non-zero. Requires `approve(0)` first.
- **Max-approval revert** (some tokens): `approve(type(uint256).max)` reverts.
- **Missing/incorrect events**: custom `transfer()`/`transferFrom()` not emitting `Transfer`, or `approve()` not emitting `Approval`. Off-chain indexers and integrations break silently.

All of these are silent integration failures - no revert, wrong state, or broken tooling.

## Detection Heuristics

**Missing Return Value**
- `require(token.transfer(...))` or `require(token.transferFrom(...))` without SafeERC20
- `bool success = token.transfer(...)` without checking that call didn't revert
- Protocol claims USDT/BNB/WBTC support but uses raw `.transfer()`

**Non-Standard Approve**
- `token.approve(spender, newAmount)` without first calling `approve(0)` or using `forceApprove`
- Re-approval in loops: `token.approve(router, amounts[i])` per-iteration
- `token.approve(spender, type(uint256).max)` without token compatibility check

**Missing Events**
- Custom ERC20 override of `transfer`/`transferFrom` that skips `emit Transfer`
- `_mint`/`_burn` override that skips `emit Transfer(address(0), to, amount)`
- Custom `approve` that skips `emit Approval`

## False Positives

- OZ `SafeERC20.safeTransfer()`/`safeTransferFrom()` used for all token operations
- OZ `SafeERC20.forceApprove()` or `safeIncreaseAllowance()` used for approvals
- Token whitelist restricted to fully ERC20-compliant tokens (verified in tests)
- OZ ERC20 base used without overriding transfer/approve/event logic
