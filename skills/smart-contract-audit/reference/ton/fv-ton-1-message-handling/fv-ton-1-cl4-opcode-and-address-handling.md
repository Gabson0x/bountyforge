# FV-TON-1-CL4 Opcode and Address Handling

## TLDR

Unhandled or silently accepted unknown opcodes, incorrect bounceable/non-bounceable address flags, and missing workchain validation each create distinct attack surfaces in message routing.

## Detection Heuristics

**Missing unknown-opcode rejection**
- `recv_internal` dispatch ends with `if / elseif` branches but no `else { throw(error::unknown_op); }` or equivalent
- Opcode 0 (plain TON transfer with no body) not handled separately - falls through to functional message handling
- Contract accepts and partially processes messages it does not understand, potentially changing state based on partial reads

**Incorrect bounceable/non-bounceable flag**
- Address prefix `store_uint(0x18, 6)` (bounceable) used when sending to undeployed user wallets - message bounces, funds returned unexpectedly
- Address prefix `store_uint(0x10, 6)` (non-bounceable) used when sending to other contracts - losing the safety net of bounce recovery on failure

**Missing workchain validation**
- Incoming `sender_address` stored or compared without calling `force_chain(WORKCHAIN)` or extracting and checking the workchain prefix
- Address passed to child contract deployment without workchain check - contract deployed in wrong workchain
- `equal_slices` comparison between addresses from different workchains silently returns false, bypassing authorization

## False Positives

- Contract deliberately acts as a passthrough or router and intentionally accepts all opcodes, forwarding them downstream
- Workchain is enforced at a higher level (deployer or factory) and all addresses in storage are guaranteed to be in the correct workchain
