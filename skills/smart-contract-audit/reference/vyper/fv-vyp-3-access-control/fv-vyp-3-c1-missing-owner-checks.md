# FV-VYP-3-C1 Missing Owner Checks

## TLDR

Vyper has no built-in access control modifiers analogous to OpenZeppelin's `onlyOwner`. Every privileged function must explicitly assert the caller's identity. Missing or misplaced `assert msg.sender == self.owner` statements leave administrative, emergency, and fund-moving functions callable by any address.

## Detection Heuristics

**State-mutating `@external` functions with no caller assertion**
- Functions that write to `self.owner`, `self.paused`, or any configuration variable contain no `assert msg.sender == ...` at the top
- `raw_call(msg.sender, b"", value=self.balance)` or similar ETH-draining call appears in a function with no access guard
- Functions named `pause`, `unpause`, `set_fee`, `upgrade`, `emergency_withdraw`, or similar administrative verbs lack any access check

**`assert` placed after state-mutating lines**
- An access check appears after a storage write or `raw_call`, meaning the side effect occurs before authorization is validated

**Owner stored in a mutable variable with no transfer guard**
- `self.owner` can be overwritten by a function that only checks `msg.sender == self.owner` but not the zero address or other invariants, allowing the owner to be burned

**`@internal` helper functions that perform privileged operations without caller checks**
- An internal function executes `raw_call` or modifies critical state, and the calling `@external` function has no access guard

## False Positives

- Functions intentionally open to all callers: `deposit`, `bid`, `enter`, or any participation function where unrestricted access is the design intent
- View or pure functions (`@view`, `@pure`) that read state but cannot modify it
- Functions guarded by an alternative mechanism such as a `paused` flag checked before execution, where the separate `pause` function itself is properly access-controlled