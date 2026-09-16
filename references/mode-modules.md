# Mode Modules — Godmod, Fuzz, X-Ray, Meme, Storage

> Split from SKILL.md v4.1.0. Load the matching module when `--expert`, `--fuzz`, `--xray`, `--meme`, or `--storage` is set. Deep versions also live under `skills/`.

---

## GODMOD — Expert Mode

When `--expert` flag is set or user requests deep analysis, activate 4 simultaneous personas:

### Persona 1: Security Researcher (Pashov/Myers Level)
- Prover-level thinking: formal invariants, mathematical proofs
- Every assumption must have a counter-example
- Every invariant must have a test

### Persona 2: Pentester (OSCP+ Mindset)
- Primitives-based thinking: what can I control?
- Business logic focus: what does the developer believe that's false?
- Chain every primitive into an exploit

### Persona 3: Senior Dev/Architect
- Full call stack reading: not just the vulnerable function, but every caller
- Dependency chain awareness: supply chain as attack surface
- Gas optimization patterns that create security holes

### Persona 4: Cracked Generalist
- Move/Rust/Solidity/TypeScript/Kotlin/Dart fluency
- EVM/Solana/Aptos internals
- Cryptographic primitives knowledge (ECDSA, EdDSA, Poseidon, BN254)

**Output rules:** No em dashes. No hedging. Pre-answer triager objections. Every claim backed by executed code.

---

## FUZZ SUITE GENERATION (Echidna/Medusa)

When `--fuzz` flag is set, run the Fizz pipeline:

### 11-Step Pipeline
1. **Tool verification** — Check echidna/medusa installed
2. **ABI extraction** — Extract from Foundry/Hardhat artifacts
3. **Protocol understanding** — Load x-ray or fallback analyzer
4. **Entry point selection** — Interactive function picker
5. **Scaffold generation** — Basic harness structure
6. **Handler generation** — Stateful function wrappers
7. **Coverage iteration** — Run medusa, measure coverage
8. **Invariant discovery** — 5 parallel agents (protocol specialist, conservation auditor, roundtrip analyst, state-transition mapper, adversarial profit maximizer)
9. **Property synthesis** — English → Solidity assertions
10. **Fuzzing campaign** — Run with time limits
11. **Validation & reporting** — Invariant violations → findings

### 5 Invariant Discovery Agents
- **Protocol Specialist:** Understands AMM/lending/staking/bridge patterns
- **Conservation Auditor:** Checks `totalAssets == Σ(balances)`, supply invariants
- **Roundtrip/Rounding Analyst:** Tests deposit→withdraw→deposit loops for profit
- **State-Transition Mapper:** Maps all state transitions, finds unreachable states
- **Adversarial Profit Maximizer:** Tries every combination to extract value

---

## X-RAY PRE-AUDIT REPORT

When `--xray` flag is set, generate a pre-audit report before deep analysis:

### Enhanced Threat Model Components
- **Protocol-type profiling:** AMM, lending, derivatives, yield, bridge, NFT, governance
- **Git-weighted attack surfaces:** Recent commits = higher risk areas
- **Temporal risk analysis:** Code age, upgrade frequency, team turnover
- **Composability dependency mapping:** What external contracts does this depend on?

### X-Ray Output
```
x-ray/
├── overview.md          # Protocol summary, architecture
├── threat-model.md      # Enhanced threat model
├── invariants.md        # Security invariants
├── integrations.md      # External dependencies
├── tests.md             # Test coverage analysis
├── developers.md        # Git history, contributor analysis
└── entry-points.md      # All external functions
```

---

## MEME COIN / TOKEN SECURITY AUDIT

When `--meme` flag is set, run the token-specific audit module.

### 8 Token-Specific Bug Classes

| # | Bug Class | Quick Grep | Impact |
|---|-----------|------------|--------|
| 1 | Hidden Mint | `function mint\|function _mint` | Unlimited token creation |
| 2 | Honeypot | `function approve\|function transferFrom` | Tokens can't be sold |
| 3 | Fee Manipulation | `swapFee\|buyFee\|sellFee` | Dynamic fee → 99% |
| 4 | LP Drain | `removeLiquidity\|withdraw` | Developer drains liquidity |
| 5 | Bonding Curve | `curveAmount\|bondingCurve` | Price manipulation |
| 6 | Authority Retention | `mintAuthority\|freezeAuthority\|owner` | Admin keeps control |
| 7 | Fake Renounce | `renounceOwnership` | Ownership not actually renounced |
| 8 | Sandwich Amplification | `getAmountOut\|priceImpact` | MEV sandwich at scale |

### Solana SPL Token Checks
```bash
# Check token authorities
spl-token display <TOKEN_ADDRESS>
# Look for: mint_authority (should be None), freeze_authority (should be None)

# Check metadata mutability
metaplex-token-metadata <TOKEN_ADDRESS>
# Look: isMutable should be false for renounced tokens
```

### Token-2022 Extension Risks
- **Transfer hooks:** Can execute arbitrary code on every transfer
- **Permanent delegate:** Delegate can transfer any holder's tokens
- **Non-transferable:** Tokens locked forever
- **Interest-bearing:** Balance changes without transfer

---

## EVM STORAGE-SAFETY ANALYSIS

When `--storage` flag is set, run the Code Sleuth protocol:

### Storage Inventory
1. Map every `storage` variable with slot number and type
2. Identify proxy/upgradeable patterns (EIP-1967, UUPS, Transparent)
3. Check for storage collisions across upgrade boundaries

### Lost-Write Detection
Pattern: Storage-backed value copied to memory, mutated, never written back
```solidity
// VULNERABLE: balance is in storage, but local copy is mutated
function withdraw(uint amount) public {
    uint balance = balances[msg.sender]; // storage → memory
    balance -= amount;                   // memory mutation
    // balance never written back to storage!
}
```

### Attacker-Influenced Storage Slot Writes
- Check if `keccak256(key)` or user-controlled values determine storage slots
- Verify that mappings use unique, non-colliding slot positions
- Check for `assembly { sstore(...) }` with attacker-influenced keys

### Upgrade Layout Hazards
- New storage variables appended at end (not inserted in middle)
- No type changes for existing slots
- Gap slots reserved for future upgrades
- Initializer vs constructor: must use initializer for proxy patterns

---

