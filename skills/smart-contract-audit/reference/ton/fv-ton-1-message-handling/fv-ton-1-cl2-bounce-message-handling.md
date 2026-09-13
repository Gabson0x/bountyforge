# FV-TON-1-CL2 Bounce Message Handling

## TLDR

Contracts that send messages but lack a bounce handler - or whose handler misparses the bounced body - leave state permanently inconsistent when the sent message fails, because there is no rollback path.

## Detection Heuristics

**No bounce handler**
- `recv_internal` does not check `msg_flags & 1` (the bounced flag) before dispatching
- State (balance credits, debt entries) is committed before `send_raw_message` with no matching recovery opcode
- Jetton `internal_transfer` sent but no handler for `op::internal_transfer` bounce

**Bounce handler present but incorrectly parsed**
- Handler does not skip the 32-bit `0xFFFFFFFF` prefix before extracting the original opcode: `int op = cs~load_uint(32)` without first calling `cs~load_uint(32)` to discard the bounce prefix
- Handler reads the opcode from the wrong position, dispatches to wrong branch, and silently ignores the bounce
- Handler catches the bounce opcode but does not revert the corresponding state change

**State committed before the send**
- `set_data()` called with updated balances/credits before `send_raw_message` - if the message bounces and the handler is missing, the state update is permanent

## False Positives

- Message sent with non-bounceable flag (`store_uint(0x10, 6)`) to a user wallet - such messages never bounce, so a bounce handler is not required
- Contract sends fire-and-forget notifications (logs) where bounce recovery is intentionally not needed and documented as such
