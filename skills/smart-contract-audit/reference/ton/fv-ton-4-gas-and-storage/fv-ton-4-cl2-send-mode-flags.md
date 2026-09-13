# FV-TON-4-CL2 Send Mode Flags

## TLDR

Incorrect `send_raw_message` mode flags can drain the contract's balance (mode 128 without reserve), cause the contract to pay gas for user operations (mode 1 with user-controlled amounts), mask critical send failures (mode +2), or accidentally destroy the contract (mode +32).

## Detection Heuristics

**Mode 128 without prior raw_reserve**
- `send_raw_message(msg, 128)` carries the entire remaining contract balance - if `raw_reserve(MIN_STORAGE, RESERVE_REGULAR)` is not called first, the contract is left with zero balance and freezes
- Mode 128 combined with mode +32 (`send_raw_message(msg, 160)`) intentionally destroys the contract - verify this is not reachable via user-triggered paths

**Mode 1 with user-controlled amounts**
- `send_raw_message(msg, 1)` instructs the VM to deduct send fees from the contract balance rather than the message value - if the message value is user-controlled and can be zero, the contract pays all fees
- Pattern: user sends 0 TON → contract builds message with mode 1 → contract pays the gas

**Mode +2 masking failures**
- `send_raw_message(msg, 2)` or `send_raw_message(msg, 3)` silently ignores send errors - if the send fails (insufficient balance, oversized message), execution continues as if it succeeded, leaving state inconsistent
- Used in non-critical notification paths but applied broadly to all sends

**Missing mode flag**
- `send_raw_message(msg, 0)` (or implicit default) when mode 64 or 128 is semantically required - message sends a fixed amount but remaining value is not forwarded

## False Positives

- Mode 128 with mode +32 is used in a self-destructing cleanup contract where destruction is the intended terminal state, gated behind admin authorization
- Mode +2 used only for optional notification messages where failure is acceptable by protocol design and no state change depends on the send succeeding
