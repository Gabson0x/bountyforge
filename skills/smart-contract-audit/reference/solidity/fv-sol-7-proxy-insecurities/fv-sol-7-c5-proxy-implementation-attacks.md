# FV-SOL-7-C5 Proxy Implementation Attack Vectors

## TLDR

Implementation contracts are not just storage targets - they are execution contexts with their own attack surface. Vulnerabilities include immutable variable context mismatch across proxies, arbitrary delegatecall exposed in the implementation, incomplete assembly fallback propagation, minimal proxy (EIP-1167) destruction when implementation is killed, and metamorphic contract substitution via CREATE2 and selfdestruct.

## Detection Heuristics

**Immutable Context Mismatch**
- `immutable` variables in implementation for addresses, chain IDs, or other per-deployment config
- Multiple proxies pointing to same implementation with different expected configurations
- `immutable` set in implementation constructor (not `initialize`) - same value forced everywhere

**Arbitrary Delegatecall**
- `target.delegatecall(data)` where `target` is caller-supplied or role-controlled but unbounded
- Implementation inherited from upgradeable library exposes generic execute function
- No whitelist or address validation on delegatecall target

**Assembly Proxy Propagation**
- Custom fallback with `delegatecall` but no `returndatacopy`
- No `switch result case 0 { revert(...) }` - swallowed failures
- `calldatacopy` absent - implementation receives empty calldata

**Minimal Proxy Destruction**
- `Clones.clone(impl)` where implementation has `selfdestruct` or unprotected `initialize`
- Implementation not protected by `_disableInitializers()` in constructor
- EIP-1167 clone factory without checking implementation is live

**Metamorphic via CREATE2**
- `CREATE2` deployment from address that can `selfdestruct` and redeploy
- Governance votes on bytecode hash but execution occurs after timelock expiry
- Pre-Dencun: `selfdestruct` + redeploy at same address with different code possible
- Post-Dencun (EIP-6780): only mitigated for non-same-tx create-destroy

## False Positives

- Per-proxy config in `initialize()` via storage variables, no `immutable` for deployment-specific values
- Delegatecall targets hardcoded as `immutable` verified library addresses
- OZ `Proxy.sol` used - complete calldata/returndata propagation correct by default
- `_disableInitializers()` in implementation constructor prevents direct initialization
- Post-Dencun deployment: `selfdestruct` no longer destroys code mid-tx
