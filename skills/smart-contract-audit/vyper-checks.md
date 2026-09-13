# Vyper-Specific Audit Checks

## Security Categories

### Access Control & Upgradeability

- Unauthorized access to sensitive functions
- Insecure constructor/init logic
- Upgradeability pattern misuse (e.g. unprotected upgradeTo)

### Fund Management

- Reentrancy vulnerabilities
- Incorrect accounting or balance tracking
- Incorrect token transfers or approvals
- Unchecked external call returns

### Vyper-Specific Issues

- Integer overflow/underflow (pre-0.3.4 versions)
- Timestamp dependencies and block manipulation
- Weak randomness sources
- Front-running vulnerabilities in MEV-sensitive logic
- Division precision errors specific to Vyper's fixed-point arithmetic

### Contract Logic Integrity

- Incorrect state transitions
- Lack of input validation leading to invariant violation
- Division precision errors
- Denial of service through unbounded operations

## Knowledge Base References

For detailed vulnerability patterns, read the relevant README then drill into case files:
- `cat $SKILL_DIR/reference/vyper/fv-vyp-1-reentrancy/readme.md` - Reentrancy attack patterns
- `cat $SKILL_DIR/reference/vyper/fv-vyp-2-integer-overflow/readme.md` - Overflow/underflow issues
- `cat $SKILL_DIR/reference/vyper/fv-vyp-3-access-control/readme.md` - Access control vulnerabilities
- `cat $SKILL_DIR/reference/vyper/fv-vyp-4-external-calls/readme.md` - External call safety
- `cat $SKILL_DIR/reference/vyper/fv-vyp-5-timestamp-dependencies/readme.md` - Timestamp manipulation
- `cat $SKILL_DIR/reference/vyper/fv-vyp-6-weak-randomness/readme.md` - Random number generation
- `cat $SKILL_DIR/reference/vyper/fv-vyp-7-front-running/readme.md` - MEV and front-running
- `cat $SKILL_DIR/reference/vyper/fv-vyp-8-division-precision/readme.md` - Fixed-point math issues
- `cat $SKILL_DIR/reference/vyper/fv-vyp-9-denial-of-service/readme.md` - DoS vulnerabilities
- `cat $SKILL_DIR/reference/vyper/fv-vyp-10-upgradeability/readme.md` - Upgrade pattern security
