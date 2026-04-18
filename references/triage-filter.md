# Triage Filter — Ecosystem Conventions & False Positive Patterns

This reference helps agents avoid wasting analysis on patterns that are
standard across the target ecosystem. Check this BEFORE deep analysis.

---

## Blockchain Node / Infrastructure Conventions

These are NEVER findings when present in L1/L2 node implementations:

| Pattern | Why It's Standard | Reference Projects |
|---------|------------------|--------------------|
| Unauthenticated operator RPC | Operator-facing, firewall is the boundary | Geth admin, CometBFT /status, Reth |
| Plaintext CL↔EL communication | Co-located processes on same machine | Lighthouse↔Geth, Prysm↔Reth |
| Plaintext local signer connection | Same-machine or VPN link | Web3Signer, TMKMS, Horcrux |
| JWT without `exp` claim | `iat` freshness (±60s) is the real check | Reth, Geth Engine API |
| Version/health endpoint public | Operational tooling, info is public on GitHub | All blockchain nodes |
| No CORS on node API | Axum/Go default = no CORS headers = browser-blocked | All node frameworks |
| Default bind to 0.0.0.0 | Dev convenience, prod uses firewall/config | All P2P software |
| Mempool-only tx filtering | Local override is standard EVM pattern | Geth, Reth, Besu |
| No rate limiting on operator API | Operator controls access via firewall | CometBFT, Geth |
| Config-driven endpoint lists | Operator sets peers/endpoints at deploy time | All P2P networks |

### Where Real Node Findings Live

| Target Area | What to Look For | Signal |
|-------------|-----------------|--------|
| Precompile access control | Caller checks, auth inconsistencies across similar precompiles | Asymmetric enforcement |
| EVM execution hooks | before_frame_init, block validation, state transitions | Check missing at execution layer but present at mempool |
| Compliance enforcement | Blocklist vs denylist enforcement depth differences | Same purpose, different layers |
| Hardfork transitions | `if hardfork.is_active()` branches | Pre/post inconsistencies |
| Cross-layer validation | Mempool vs execution vs consensus | Same check, different behavior |
| Consensus validation | Vote counting, signature verification, timeout handling | Off-by-one, threshold bugs |

---

## Smart Contract Conventions (EVM/Solidity)

These are NEVER findings in well-structured Solidity codebases:

| Pattern | Why It's Standard |
|---------|------------------|
| `unchecked` blocks in Solidity 0.8+ with correct math reasoning | Gas optimization, overflow impossible by logic |
| Explicit narrowing casts in 0.8+ | Compiler checks, developer intentional |
| MINIMUM_LIQUIDITY burn on first LP deposit | Uniswap V2 standard, prevents price manipulation |
| `SafeERC20` usage | Handles non-standard tokens correctly |
| `nonReentrant` on single contract | Only flag cross-contract reentrancy |
| Two-step admin/ownership transfer | Security pattern, not a bug |
| Protocol-favoring rounding (consistent direction) | Standard unless it compounds |
| `onlyOwner` / `onlyAdmin` on admin functions | Centralization by design unless exploit path exists |

### Where Real Smart Contract Findings Live

| Target Area | What to Look For |
|-------------|-----------------|
| Cross-function state inconsistency | Function A guards a write, Function B writes same state without guard |
| Token accounting gaps | Mint/burn/transfer paths that skip balance validation |
| Oracle trust boundaries | Price feed manipulation via flash loans, stale price acceptance |
| Upgrade proxy patterns | Storage collision, unguarded upgradeability |
| External call trust | Callbacks from untrusted tokens, reentrancy across contracts |

---

## Web/API Conventions

These are NEVER findings in properly configured web applications:

| Pattern | Why It's Standard |
|---------|------------------|
| Rate limiting on read endpoints | DoS hardening, not security boundary |
| CSRF on logout | No security impact without session fixation |
| Self-XSS without escalation | No victim, attacker harms themselves |
| Stack traces in dev/staging mode | Not production exposure |
| Generic error messages like "500 Internal Server Error" | Standard error handling |
| Missing security headers on non-sensitive pages | Hardening, not vulnerability |
| GraphQL introspection on dev/internal instances | Only flag on production |

### Where Real Web Findings Live

| Target Area | What to Look For |
|-------------|-----------------|
| Auth flow implementation | Token handling, session management, OAuth state |
| Object-level authorization | IDOR across all resource endpoints |
| File upload handling | Type bypass, path traversal, XXE via document formats |
| Deserialization endpoints | Untrusted input to deserializers |
| Business logic state machines | Step skipping, state manipulation, race conditions |

---

## Asymmetry Detection Guide

The highest-signal finding pattern across ALL target types is
**internal inconsistency**: the codebase contradicts its own security model.

### How to Build an Enforcement Matrix

For every security mechanism in the codebase, map which layers enforce it:

```
| Mechanism  | Layer 1    | Layer 2      | Layer 3    |
|-----------|------------|--------------|------------|
| Check A   | ✅ present | ✅ present   | ✅ present |
| Check B   | ✅ present | ❌ MISSING   | ✅ present |
```

**Gaps where another row has coverage = strongest findings.**

### Layer Names by Target Type

| Target Type | Layers to Map |
|-------------|--------------|
| Blockchain node | Mempool → EVM execution → Consensus validation |
| Smart contract | Modifier → Function body → Cross-contract call |
| Web application | Middleware → Handler → Database query |
| API | Auth middleware → Route handler → Business logic |

### Validation Before Reporting

A gap in the matrix is a finding ONLY if:
1. Both mechanisms serve the same security/compliance purpose
2. The gap enables a concrete bypass path
3. The bypass path is achievable by the threat model's actors
4. The precondition is NOT already a full compromise

---

## Target Selection Priority

When choosing where to focus analysis tokens:

### HIGH VALUE (spend tokens here)
- Custom security logic (hand-written auth, bespoke precompiles)
- Cross-layer enforcement boundaries
- Hardfork/migration transition code
- Compliance-critical mechanisms (blocklist, denylist, KYC gates)
- Token/value transfer paths
- Signature verification and cryptographic operations

### LOW VALUE (don't spend tokens here)
- Configuration parsing and CLI handling
- Logging, metrics, health check endpoints
- Test utilities and mock code
- Standard library/framework security
- Error message formatting
- P2P networking defaults
- Version endpoints and build info
