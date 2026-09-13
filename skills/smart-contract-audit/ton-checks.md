# TON (FunC/Tact) Specific Audit Checks

## TON/FunC/Tact Audit Tricks

- Check every `recv_internal` handler for `transfer_notification` - verify `sender_address` is compared against a stored, initialized Jetton wallet address, not just the `from_user` field inside the payload body
- Look for `accept_message()` in `recv_external` handlers - confirm it appears AFTER signature verification and seqno check, never before
- Search for `send_raw_message` calls and record the mode flag on each - modes 128 and +32 are high-risk; mode 1 with user-controlled amounts drains contract balance
- Verify every `raw_reserve()` call uses the correct reserve mode and minimum value; contracts without `raw_reserve` before sends are susceptible to storage-fee freezing
- Check all `recv_internal` handlers for a default/else branch - missing unknown-opcode handling or missing `throw(error::unknown_op)` can silently accept malformed messages
- Look for FunC boolean variables: if `-1`/`0` (true/false) is expected but `1`/`0` is used and later inverted with `~`, the logic is inverted - `~1 == -2` is truthy, not falsy
- For any contract that sends messages, trace whether a bounce handler exists and whether it correctly skips the 32-bit `0xFFFFFFFF` prefix before re-parsing the original opcode
- Confirm `end_parse()` is called after every message and storage deserialization - missing `end_parse()` silently ignores trailing bytes that may indicate injection or format mismatch
- Verify all administrative opcodes (`change_admin`, `upgrade`, `withdraw`) check `sender_address` against a stored admin value; absence of `throw_unless(error::not_owner, ...)` is a critical miss
- In multi-step message chains (A→B→C), verify that sufficient TON value propagates through each hop and that bounce handling restores state at every step

## Security Categories

### Message Handling and Sender Validation

- Missing `throw_unless` comparing `sender_address` to stored Jetton wallet address in `transfer_notification`
- Trusting `from_user` in notification payload body as proof of depositor identity
- `recv_internal` handling privileged ops without any sender check
- No `throw(error::unknown_op)` for unrecognized opcodes
- Missing handling for opcode 0 (plain TON transfer) separately from functional messages
- Incorrect bounceable/non-bounceable flag (0x18 vs 0x10 in address prefix bits)
- Missing workchain validation (`force_chain()`) on incoming addresses
- Bit/ref layout mismatch between sender and receiver

### Bounce and Message Lifecycle

- No bounce handler for messages that modify state before sending
- Bounce handler present but not skipping 32-bit `0xFFFFFFFF` prefix before parsing
- State change committed before message send with no rollback on bounce
- Sending to non-existent accounts without StateInit included in message
- Missing insufficient-gas propagation in multi-hop chains

### Authorization and Replay Protection

- `accept_message()` called before signature or seqno check in `recv_external`
- Missing `seqno` check or seqno incremented after execution instead of before
- Admin operations reachable without `equal_slices(sender_address, admin_address)` guard
- Single-step admin transfer with no pending/confirm pattern
- Contract initialization function callable by anyone or re-callable after deployment
- No idempotency or nonce on internal-message operations that should be one-time

### FunC Language Footguns

- Boolean values stored as `1`/`0` instead of `-1`/`0`, then used with `~` operator
- `load_int()` used for amounts or sizes that should never be negative
- Function containing `send_raw_message()`, `set_data()`, `set_code()`, or `raw_reserve()` missing `impure` specifier
- Global variables read before `load_data()` is called, returning zero/default instead of stored values
- `throw_unless` and `throw_if` polarity swapped - inverts the security check
- Custom exit codes in range 0–127 (TON-reserved) causing confusion with system errors

### Gas and Storage Economics

- `forward_ton_amount` read from user message and used directly without bounding against `msg_value`
- `send_raw_message` with mode 128 without prior `raw_reserve()` to protect minimum balance
- `send_raw_message` with mode 1 and user-controlled amounts, making contract pay gas
- Mode +2 (ignore errors) masking critical send failures
- Mode +32 reachable in non-destructive paths, accidentally destroying the contract
- No `raw_reserve(MIN_TON_FOR_STORAGE, RESERVE_REGULAR)` before sending
- `accept_message()` called before cheap validation, enabling gas draining via spam
- Unbounded dict iteration or loop over user-controlled data in a single transaction
- Contract balance reaching zero through operations without minimum reserve enforcement

### TON Actor Model and Asynchronous Execution

- State updated before message send - no "processing" lock, allowing concurrent modification
- Callback handler reads state cached from before the send, not re-read from c4
- Assuming cross-contract message ordering from different senders
- Multi-message operation with no bounce recovery for any of the sent messages
- `my_balance` or raw contract balance used for business logic - manipulable by anyone sending TON directly
- Logical time ordering relied upon for messages from different source contracts

### Contract Lifecycle

- `set_code()` followed by logic that assumes new code is active in the same transaction
- `set_code()` without corresponding `set_data()` migration - new code misinterprets old storage layout
- No version field in storage to detect format mismatch after upgrade
- `set_code()` reachable without admin authorization or without timelock
- `send_raw_message` with mode flag +32 in refund or error paths
- Address computation for child contract using different code or data than actual StateInit
- Missing StateInit in messages that must deploy child contracts
- Method IDs (CRC16 of function name) colliding between get methods

### Token Standards (TEP-74 Jetton, TEP-62 NFT)

- Jetton wallet balance modified by messages without validating sender is the minter
- `total_supply` not decremented in `burn_notification` handler
- `burn_notification` itself never sent after wallet burn
- Jetton getters `get_wallet_address` / `get_jetton_data` missing or non-standard
- NFT `next_item_index` not atomically incremented, allowing duplicate or arbitrary indices
- NFT owner update handler missing `equal_slices(sender, owner_address)` check
- `store_coins` / `load_coins` mixed with `store_uint` / `load_uint` on the same field, corrupting layout
- TEP-74 or TEP-62 op codes not matching specification, breaking ecosystem interoperability

### Tact-Specific Issues

- Tact `Ownable` trait used but `self.requireOwner()` absent from admin-only receive handlers
- `receive()` fallback handler contains business logic that runs on every plain TON transfer
- Tact struct/message serialization not matching FunC message layout in cross-language contracts
- `map<K,V>` used for unbounded collections without size tracking or iteration limits
- Tact `init` function re-callable post-deployment due to missing `is_initialized` guard
- Cross-language error code reliance broken by Tact's string-based `require()` vs numeric `throw_unless()`

### DeFi Protocol Patterns

- Oracle price consumed without `now - last_update > MAX_STALENESS` check
- Oracle address not validated on price update - any contract can submit fake prices
- Share/vault price derivable from raw token balance, enabling first-depositor inflation attack
- Liquidation bonus does not cover gas cost for minimum viable position size
- Slippage parameter derived from on-chain pool state instead of user-supplied value
- Missing `deadline` parameter on swap operations, allowing delayed-execution attacks
- Bridge message replay: no nonce or message-hash deduplication for processed bridge transfers
- Governance vote weight from current balance, not historical snapshot - flash vote possible
- Governance proposal execution without timelock

## Knowledge Base References

For detailed vulnerability patterns, read the relevant README then drill into case files:
- `cat $SKILL_DIR/reference/ton/fv-ton-1-message-handling/readme.md` - Sender validation, bounce, opcodes, serialization
- `cat $SKILL_DIR/reference/ton/fv-ton-2-access-control/readme.md` - Authorization, replay protection, admin patterns
- `cat $SKILL_DIR/reference/ton/fv-ton-3-arithmetic-errors/readme.md` - Integer/boolean errors, precision, rounding
- `cat $SKILL_DIR/reference/ton/fv-ton-4-gas-and-storage/readme.md` - Gas management, send modes, storage fees
- `cat $SKILL_DIR/reference/ton/fv-ton-5-async-execution/readme.md` - TON actor model, async reentrancy, race conditions
- `cat $SKILL_DIR/reference/ton/fv-ton-6-contract-lifecycle/readme.md` - Deployment, upgrades, StateInit, set_code
- `cat $SKILL_DIR/reference/ton/fv-ton-7-token-standards/readme.md` - Jetton (TEP-74), NFT (TEP-62), token accounting
- `cat $SKILL_DIR/reference/ton/fv-ton-8-tact-language/readme.md` - Tact-specific vulnerability patterns

For protocol-type-specific DeFi audit context (preconditions, historical findings, remediation):
- `cat $SKILL_DIR/reference/ton/protocols/oracle.md` - Oracle integration patterns (async delivery, fake sender, staleness)
- `cat $SKILL_DIR/reference/ton/protocols/amm-dex.md` - AMM and DEX patterns (slippage, deadline, invariant, front-running)
- `cat $SKILL_DIR/reference/ton/protocols/lending.md` - Lending and vault patterns (async liquidation, vault inflation, bad debt)
- `cat $SKILL_DIR/reference/ton/protocols/staking.md` - Staking and reward patterns (accumulator ordering, flash stake, cooldown griefing)
- `cat $SKILL_DIR/reference/ton/protocols/bridge-governance.md` - Bridge replay and governance patterns (deduplication, flash vote, timelock)
