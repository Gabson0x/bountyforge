# FV-SOL-5-C5 Event Misreporting

## TLDR

Events emit incorrect values - such as a cumulative balance instead of the current operation amount - causing off-chain indexers, monitoring systems, and oracles to record wrong data while on-chain state may be correct.

## Detection Heuristics

**Post-Update State Emitted Instead of Operation Delta**
- Event parameter passes `balances[msg.sender]` (cumulative post-update value) when the deposit delta `msg.value` should be reported
- State variable updated before the `emit`, and the emitted field reads the updated state rather than a pre-captured local variable
- Event field named `amount` or `value` that actually emits a running total or accumulated balance

**Missing Emit on Critical State Change**
- Role grant, ownership transfer, or privileged parameter update executed without emitting an event
- Multiple code paths modify the same state variable but only some paths emit the corresponding event
- Conditional logic causes the emit to be skipped on one branch (e.g., emit inside an `if` without a matching emit in the `else`)

**Wrong Event or Wrong Parameters**
- Event emitted with arguments in wrong order (e.g., `emit Transfer(to, from, amount)` instead of `emit Transfer(from, to, amount)`)
- Stale local variable captured before state update used in emit, reporting the pre-state when post-state is expected
- Event emitted for every loop iteration using a per-item value when a single summary event was intended

## False Positives

- Emitted value is explicitly the operation delta (`msg.value` or the `amount` parameter) not the post-state balance
- Local variable captures the value before state update and is passed to emit: `uint256 depositAmount = msg.value; balances[msg.sender] += depositAmount; emit Deposit(msg.sender, depositAmount);`
- Event documented as intentionally emitting cumulative balance with explicit naming (e.g., `newBalance`)
