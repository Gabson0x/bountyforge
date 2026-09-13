# Sui Move Specific Audit Checks

## Sui/Move Audit Tricks

- Check every function accepting `Coin<T>` or generic `<T>` - confirm `T` is validated against a whitelist or phantom type constraint on the container; unvalidated generics are the number-one critical finding in real Move audits
- Search for `public(package) entry` or `public entry` function declarations - `entry` overrides `public(package)` visibility and makes the function callable by any transaction; internal-only functions must not carry the `entry` modifier
- Locate all struct definitions with `copy` or `drop` abilities and verify they carry no financial obligation semantics - objects with debt, flash-loan receipts, or collateral locks must have no abilities
- Verify every hot potato (flash loan receipt) struct has NO abilities (`copy`, `drop`, `store`, `key` all absent) and contains a `pool_id: ID` field binding it to the originating pool
- Check all shared objects for a `version: u64` field and verify every public function asserts `obj.version == CURRENT_VERSION`
- Inspect `init` functions and confirm no business logic assumes `init` re-runs on package upgrade - upgrades do not re-execute `init`; a migration function must exist for post-upgrade initialization
- Search `Move.toml` for git dependencies without pinned revision or tag - unpinned dependencies can change silently, importing vulnerabilities
- Verify `UpgradeCap` ownership: must be held by multi-sig, governance, or timelocked; single EOA holding it is a critical finding
- For time-sensitive operations (`clock::timestamp_ms`), check that constants have `_MS` suffix and that all comparisons use the same unit - milliseconds vs seconds confusion is a high-severity recurring bug
- In staking/reward contracts, confirm `update_rewards()` or reward accumulator update is the first operation in every stake/unstake function, before any balance change
- Check every `table::add` and `dynamic_field::add` call for a preceding `table::contains` / `dynamic_field::exists_` check - missing existence check causes DoS on duplicate entries
- For lending protocols, verify oracle price is checked for both staleness (`last_update`) and confidence interval width; accepting a stale or low-confidence price is a critical finding
- Inspect multi-return functions returning two values of the same type - verify callers destructure in the correct order; transposed return values silently corrupt all arithmetic

## Security Categories

### Object Model and Abilities

- Struct with `copy` ability holding value-bearing semantics (token, NFT, badge)
- Struct with `drop` ability holding obligation semantics (debt record, flash loan receipt, collateral lock)
- Struct with `store` ability wrapping a sensitive capability, allowing it to be hidden or transferred outside protocol control
- Object wrapped inside a malicious contract with no guaranteed unwrap path - permanent loss
- Dynamic object field used for "hidden" objects - child ID is discoverable by indexers
- Dynamic fields not cleaned up before parent object deletion - value permanently orphaned
- `transfer::share_object` or `transfer::freeze_object` callable without capability check

### Access Control and Capabilities

- Privileged function callable without requiring a capability object (`AdminCap`, `TreasuryCap`)
- Address-based access control (`ctx.sender() == @admin`) instead of capability pattern - hardcoded address breaks on upgrade
- Capability created outside `init` without requiring an existing capability - unrestricted minting
- One-time witness (OTW) pattern absent from coin/token type creation
- Function marked `public(package) entry` when it should be callable from outside via PTB but not raw transaction - or vice versa
- Internal function declared `public` instead of `public(package)`, exposing internal logic to external callers
- Sender address accepted as a function parameter instead of derived from `tx_context::sender(ctx)`
- Generic capability `RoleCap<T>` used for authorization without asserting concrete type of `T`
- Object relationship not validated when two related objects (vault + config, position + pool) are passed together
- `Publisher` object not secured post-init - enables spoofed `Display` objects

### Package Upgrades and Lifecycle

- `init` logic depended upon to run on package upgrade - upgrades do not re-execute `init`
- Package upgrade does not re-link updated dependencies - old dependency version continues in use
- Shared object missing `version: u64` field - no mechanism to enforce "upgrade complete"
- Every public function does not check `obj.version == CURRENT_VERSION`
- Struct fields reordered or removed in upgrade - breaks deserialization of existing on-chain objects
- State migration function absent after upgrade that introduces new struct fields
- Upgrade introduces init-like function callable post-deployment to re-create capabilities
- `UpgradeCap` held by single EOA without timelock or multi-sig
- `UpgradeCap` destroyed prematurely (package immutable) before critical bugs can be fixed
- Upgrade policy more permissive than necessary (`compatible` when `dep_only` suffices)
- Git dependency in `Move.toml` without pinned revision or tag

### Shared Objects and PTBs

- Shared object mutated concurrently without version/sequence check - lost update
- Shared object used unnecessarily where owned-object pattern would prevent contention
- Flash loan hot potato has `drop` or `store` ability - borrower can discard or defer repayment
- Flash loan repay function does not validate `receipt.pool_id == object::id(pool)`
- Flash loan `start` callable multiple times in one PTB - resets snapshot, allows underpayment
- PTB flash loan enables atomic price manipulation: borrow → manipulate → exploit → repay
- Protocol has no pause mechanism - no way to halt operations on vulnerability discovery
- Pause flag not checked on all public functions - attacker routes through unpaused path
- `clock::timestamp_ms` not used for time-sensitive operations
- Time constants mix milliseconds and seconds - locks effectively instant or years-long
- Missing `deadline_ms` parameter on swap / deposit operations
- Unbounded loop or vector iteration causes gas exhaustion DoS on large state
- `table::add` or `dynamic_field::add` without preceding existence check - DoS on duplicate key

### Arithmetic and Type Safety

- Bitwise left-shift (`<<`) on financial values without explicit overflow check - Move does not check bit-shift overflow (Cetus hack vector)
- Custom math library overflow not caught by Move's default arithmetic checks
- Division before multiplication - early truncation to zero exploitable on small amounts
- Division by zero possible when divisor is user-controlled or pool state
- Integer underflow on subtraction without prior bounds check
- Narrowing cast (u128 → u64, u64 → u8) without `assert!(value <= MAX_TYPE)` bounds check
- Rounding consistently favors the user instead of the protocol - slow pool drain
- Constants contain wrong digit count (MAX_U64, SECONDS_PER_DAY, precision constants)
- Multi-return function with same-type values destructured in wrong order by callers
- Double scaling: interest index multiplication applied twice in same calculation

### Token and Coin Accounting

- `Balance<T>` and `Coin<T>` used interchangeably without consistent accounting
- First-depositor vault inflation: attacker mints 1 share then donates tokens to inflate share price
- `coin::split` or `coin::join` with internal tracking mismatch - creates or destroys value silently
- Total supply not updated atomically on every deposit/withdraw
- Zero-share mint not prevented (`assert!(shares > 0)` absent)
- Round-trip profitable: `deposit(X) → withdraw(all)` returns more than X
- Rounding direction: deposits should round DOWN (fewer shares), withdrawals should round UP (fewer tokens)
- Reward accumulator not updated before balance change - new staker earns historical rewards
- Fee collection increments a balance with no corresponding `withdraw_fees` function
- `balance::destroy_zero` called on potentially non-zero balance - permanent fund loss
- Self-transfer allowed: triggers fee/reward snapshots without economic activity

### Oracle and DeFi Protocols

- Oracle price used without staleness check (`clock_ms - oracle.last_update_ms <= MAX_STALE_MS`)
- Oracle confidence interval not validated - wide confidence means unreliable price
- Oracle object ID not validated - fake oracle accepted
- Single oracle source with no fallback or multi-source aggregation
- Spot pool price or reserve ratio used for valuation - manipulable within same PTB via flash loan
- Reference price not stored at position open time - settlement uses live price retroactively
- Slippage derived from on-chain pool state instead of user-supplied `min_amount_out`
- Liquidation bonus does not cover transaction cost for minimum-size positions
- Self-liquidation profitable (bonus exceeds penalty)
- Interest accrual continues during protocol pause - users face unexpected charges on unpause
- Bad debt not socialized - residual debt creates permanent accounting hole
- Reward accumulator updated after balance change - incorrect distribution (Thala Labs vector)
- No minimum staking duration - flash stake/unstake captures rewards in same epoch

### NFT, Kiosk, and Governance

- NFT extracted from Kiosk without completing transfer policy rules (royalties, allowlist)
- `KioskOwnerCap` not properly secured - anyone can extract NFTs
- `Display` object modifiable without Publisher - enables metadata spoofing
- Governance vote weight from current balance - flash vote possible
- Governance execution without timelock between passage and execution
- Quorum calculated from circulating supply instead of total supply
- ZK proof replay - no nullifier stored after verification
- ZK public inputs do not bind to on-chain action parameters - proof intent mismatch
- Bridge message replay - no nonce or hash deduplication

## Knowledge Base References

For detailed vulnerability patterns, read the relevant README then drill into case files:
- `cat $SKILL_DIR/reference/move/fv-mov-1-object-model/readme.md` - Abilities (copy/drop/store), dynamic fields, wrapping attacks
- `cat $SKILL_DIR/reference/move/fv-mov-2-access-control/readme.md` - Capability pattern, visibility, sender spoofing, phantom types
- `cat $SKILL_DIR/reference/move/fv-mov-3-upgrade-safety/readme.md` - init assumptions, upgrades, version checks, struct evolution
- `cat $SKILL_DIR/reference/move/fv-mov-4-shared-objects-concurrency/readme.md` - Shared objects, PTBs, hot potato, time/clock
- `cat $SKILL_DIR/reference/move/fv-mov-5-arithmetic-errors/readme.md` - Overflow, precision loss, rounding, casts, constants
- `cat $SKILL_DIR/reference/move/fv-mov-6-token-accounting/readme.md` - Coin/Balance, supply invariants, fees, dust
- `cat $SKILL_DIR/reference/move/fv-mov-8-advanced-patterns/readme.md` - Real-world exploits, generic type confusion, flash loan binding

For protocol-type-specific DeFi audit context (preconditions, historical findings, remediation):
- `cat $SKILL_DIR/reference/move/protocols/oracle.md` - Oracle patterns (Pyth on Sui, staleness, confidence, fake injection)
- `cat $SKILL_DIR/reference/move/protocols/amm-dex.md` - AMM and DEX patterns (CLMM tick arithmetic, flash swap, shared object concurrency)
- `cat $SKILL_DIR/reference/move/protocols/lending.md` - Lending patterns (vault inflation, health factor, liquidation dust, self-liquidation)
- `cat $SKILL_DIR/reference/move/protocols/staking.md` - Staking patterns (accumulator ordering, flash stake via PTB, receipt duplication, validator commission)
- `cat $SKILL_DIR/reference/move/protocols/governance.md` - Governance and bridge patterns (UpgradeCap, AdminCap, flash vote, timelock, bridge replay, ZK nullifier)
