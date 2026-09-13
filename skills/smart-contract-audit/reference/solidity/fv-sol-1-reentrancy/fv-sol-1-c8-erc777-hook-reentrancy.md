# FV-SOL-1-C8 ERC777 Hook Reentrancy

## TLDR

ERC777 tokens are backward-compatible with ERC20 but fire `tokensToSend` (on sender) and `tokensReceived` (on recipient) hooks via the ERC1820 registry on every transfer, including ERC20-style `transfer()` and `transferFrom()`. A protocol that uses standard ERC20 calls against what it believes is an ERC20 token unknowingly grants the sender or recipient a callback, enabling reentrancy.

## Detection Heuristics

**ERC20-Compatible Call That May Trigger ERC777 Hook**
- `transfer()` or `transferFrom()` called before state updates on a token whose type is not statically restricted
- `IERC20(token).transferFrom(msg.sender, address(this), amount)` followed by `balances[msg.sender] += amount` - hook fires before the state update
- `token.transfer(recipient, amount)` before any accounting update - `tokensReceived` fires on recipient

**Insufficient Token Type Restriction**
- Token whitelist does not explicitly exclude ERC777 (identified by ERC1820 interface registration: `IERC1820Registry.getInterfaceImplementer(token, keccak256("ERC777Token"))`)
- Protocol accepts arbitrary `address token` parameter with no interface check
- Whitelist populated by governance or admin without an ERC777 exclusion rule

**Hook Attack Vectors**
- `tokensToSend` fires on sender - enables reentry from sender's registered hook contract during `transferFrom`
- `tokensReceived` fires on recipient - enables reentry from recipient's registered hook contract during `transfer`
- Both hooks execute before the ERC777 transfer is considered complete, while the calling contract's state may be mid-update

## False Positives

- CEI - all state committed before transfer
- `nonReentrant` on all entry points that accept external tokens
- Token whitelist explicitly excludes ERC777 (no ERC1820 `IERC777Token` implementers accepted)
- Protocol deploys its own token (known not to be ERC777)
