# Anchor (Solana) Specific Audit Checks

## Solana/Anchor Program Tricks

- Check if PDA derivations use all required seeds and verify bump seeds are canonical
- Look for CPI calls that don't validate the target program ID matches expected program
- Verify if account validation checks both owner and discriminator for all account types
- Search for instructions that don't verify signer authority for accounts being modified
- Check if account reallocation properly handles rent exemption calculations
- Look for missing close constraints that leave accounts with non-zero data accessible
- Verify if program-derived addresses validate all derivation parameters
- Check Token-2022 token transfers use `transfer_checked` not legacy `spl_token::transfer`; confirm transfer hook account is included in CPI and the hook program is not None
- Verify compute budget instructions (`SetComputeUnitLimit`) in transaction cannot be injected or overridden by users ahead of business-logic instructions; compute exhaustion is a DoS vector
- Search all `invoke_signed` call sites for seeds derived from attacker-controlled account data; seeds must be validated before use as a signer identity
- Look for oracle price reads missing any of: staleness check against clock sysvar, confidence interval check, status/trading-halt check, and circuit breaker for extreme price deviation
- Verify reward and staking accumulator index values are updated before any balance or share change in the same instruction; index-after-balance ordering allows reward theft

## Security Categories

### Account Constraints & Validation

- Missing or incorrect `#[account]` constraints
- Lack of `has_one`, `init`, `close`, or signer checks
- Mutable accounts without proper authority enforcement
- Trying to modify an account without checking if it's writeable
- Trying to access account data without ownership checks
- Usage of UncheckedAccount without manual ownership check
- Usage of UncheckedAccount without manual signer check
- No is_initialized check when operating on an account
- Missing account constraints
- Using ctx.remaining_accounts without non-zero data check
- No reload after account mutation
- Not validating a set address

### PDA & Seed Safety

- Seed collisions or reused seeds across programs
- Missing `bump` seeds or derivations that can be hijacked
- Missing PDA initialization check
- Forced seed de-bump
- Exposed PDA seeds
- Lack of proper PDA validation for signers

### CPI & Instruction Safety

- Unchecked CPI calls to untrusted programs
- Incorrect handling of cross-program invocations
- Dangerous use of `invoke_signed` without control validation
- Signing arbitrary programs without privilege checks
- Insecure CPIs using unchecked accounts
- Passing owner-checked accounts in CPI
- Reusing instruction parameters leading to exploits
- Missing signer checks in CPIs
- Account confusion with system program

### Deserialization & Instruction Data

- Use of unchecked `AccountInfo` directly
- Manual deserialization from instruction data without checks
- Logic depending on instruction index or ordering

### Error Handling

- Missing error checks after operations
- Improper error propagation
- Lack of meaningful error messages

### Token Operations

- Improper token mint/burn operations
- Missing token account validation
- Incorrect authority checks for token operations

### System Account Validation

- Missing system account checks
- Improper account initialization
- Rent exemption violations

### Type Cosplay

- Account type confusion
- Missing discriminator checks
- Improper account casting

### Closing Accounts

- Closing accounts without zeroing data and setting a closed discriminator
- Operations on accounts marked as closed
- Unintended closure by close constraint

### Oracle & Price Feeds

- Oracle price read without staleness check against `Clock` sysvar
- Confidence interval not validated against an acceptable threshold
- Oracle status or trading-halt flag not checked before use
- Using on-chain spot price instead of a TWAP or aggregated feed
- Accepting oracle accounts not matching a hardcoded expected address (fake oracle injection)
- Retroactive oracle price applied to a transaction that occurred in a different slot
- Flash loan used to manipulate on-chain oracle within a single transaction

### DeFi Patterns

- Vault share issuance using total supply before accruing pending interest or rewards
- Deposit-then-immediate-withdraw round trip extracting value via rounding gap
- Missing minimum deposit or withdrawal fee to make precision-gap attacks uneconomical
- Slippage tolerance of 0 or derived from on-chain state in the same transaction
- Lamport balance invariant not preserved across CPI chains
- Reward accumulator index updated after balance change allowing reward theft
- Cooldown or unlock period bypassable via flash loan entering and exiting in one slot

### Token-2022 Extensions

- Token-2022 transfer hook not invoked or hook account missing from CPI
- Interest-bearing mint balance read without normalizing for accrued interest rate
- Transfer fee not accounted for when computing expected received amount
- Freeze authority on accepted mint not verified to be revoked
- Close authority on Token-2022 mint can brick protocol positions

### Compute & Program Management

- Compute budget limit instruction injected ahead of business-logic instructions in the same transaction, causing DoS
- Vec or array initialization with declared capacity but uninitialized elements accessed as if populated
- Upgrade authority on a dependency program not pinned or audited; silent behavior change after upgrade
- Log output truncated by compute limit, hiding security-relevant events from off-chain monitors

## Knowledge Base References

For detailed vulnerability patterns, read the relevant README then drill into case files:
- `cat $SKILL_DIR/reference/anchor/fv-anc-1-arithmetic-operations/readme.md` - Math overflow/underflow
- `cat $SKILL_DIR/reference/anchor/fv-anc-2-signer-checks/readme.md` - Signer validation issues
- `cat $SKILL_DIR/reference/anchor/fv-anc-3-account-ownership-validations/readme.md` - Account validation
- `cat $SKILL_DIR/reference/anchor/fv-anc-4-pda-security/readme.md` - PDA vulnerabilities
- `cat $SKILL_DIR/reference/anchor/fv-anc-5-cross-program-invocation-cpi/readme.md` - CPI security
- `cat $SKILL_DIR/reference/anchor/fv-anc-6-error-handling/readme.md` - Error handling patterns
- `cat $SKILL_DIR/reference/anchor/fv-anc-7-token-operations/readme.md` - Token security including Token-2022
- `cat $SKILL_DIR/reference/anchor/fv-anc-8-system-account-validation/readme.md` - System account checks
- `cat $SKILL_DIR/reference/anchor/fv-anc-9-type-cosplay/readme.md` - Type confusion
- `cat $SKILL_DIR/reference/anchor/fv-anc-10-closing-accounts/readme.md` - Account closure security
- `cat $SKILL_DIR/reference/anchor/fv-anc-11-state-management/readme.md` - Slippage, lamport invariant, DoS, time units, reward accumulator ordering
- `cat $SKILL_DIR/reference/anchor/fv-anc-13-program-management/readme.md` - Compute budget, upgrade authority, program init

For protocol-type-specific DeFi audit context (preconditions, historical findings, remediation):
- `cat $SKILL_DIR/reference/anchor/protocols/oracle.md` - Oracle integration patterns
- `cat $SKILL_DIR/reference/anchor/protocols/lending.md` - Lending and vault protocols
- `cat $SKILL_DIR/reference/anchor/protocols/staking.md` - Staking and reward protocols
- `cat $SKILL_DIR/reference/anchor/protocols/amm-dex.md` - AMM and DEX protocols
- `cat $SKILL_DIR/reference/anchor/protocols/governance.md` - Governance and authority management
