# Al-Mizaan v3 — 7-Gate Validation Framework

Integrated from [Bug Bounty Intelligence MCP](https://github.com/holistis/bug-bounty-intelligence-mcp) by holistis. Trained on 27,681 Sherlock/Code4rena findings, validated against 1,032 exactly-reconciled findings across 10 contests.

## The 7 Gates

Only findings that survive all 7 gates are reported. Each gate is a kill-switch — fail any single gate and the finding is eliminated.

### Gate 1: Code Reading (Literal, Not Docs)
Read what the code actually does, not what the documentation says it does. Documentation is aspirational; code is authoritative.

- Does the code path actually execute the vulnerable operation?
- Are you reading the deployed bytecode or just the source?
- Is the behavior you're describing visible in the code, or are you inferring it from comments/naming?

**Kill if:** The vulnerability exists only in documentation, comments, or naming conventions — not in executable code paths.

### Gate 2: Reachability Chain
Map the exact call path from any external entry point to the vulnerable operation.

- Can an external caller reach this code without bypassing another security check?
- Is the code behind a modifier, require statement, or role gate?
- Does the deployment configuration actually expose this path?

**Kill if:** No complete, unbroken call chain exists from an external entry point to the vulnerable code.

### Gate 3: Threat Model (Who Can Trigger It)
Define exactly who can trigger the vulnerability and what they need.

- Is the trigger a trusted actor (owner, admin, governance)?
- If trusted-actor-only: is there a governance delay, multisig, or timelock?
- Can an untrusted user become the trigger through a separate vulnerability?

**Kill if:** Only a trusted actor with no bypass path can trigger it, and the protocol explicitly accepts this risk.

### Gate 4: Invariant Breach
Identify which protocol invariant the vulnerability breaks.

- What property of the system is violated?
- Is this invariant explicitly stated in the protocol's documentation/spec?
- Would the protocol's existing test suite catch this if the invariant were encoded?

**Kill if:** No identifiable invariant is breached — the behavior is unexpected but not contract-breaking.

### Gate 5: Protocol Intent
Determine whether the behavior contradicts the protocol's intended design.

- Would the protocol designers consider this a bug or a feature?
- Is this behavior documented as intentional (e.g., "owner can pause")?
- Does the behavior align with how similar protocols operate?

**Kill if:** The behavior matches the protocol's documented intent, even if it's suboptimal.

### Gate 6: Impact (Real Financial Damage)
Quantify the concrete harm in the protocol's native terms.

- How much value can be extracted? (Exact amount, not "could be significant")
- Is the attack profitable after gas costs?
- Can it be performed atomically (single transaction) or does it require sustained manipulation?

**Kill if:** The impact is theoretical, unquantifiable, or requires unrealistic market conditions.

### Gate 7: Formal Proof (Reproducible PoC)
Produce a working proof of concept that demonstrates the full attack path.

- Does the PoC execute successfully against a mainnet fork or local testnet?
- Is every step of the attack reproducible from the PoC alone?
- Would a third-party auditor be able to verify the finding from the PoC?

**Kill if:** No working PoC exists, or the PoC relies on conditions that cannot be replicated.

---

## Application to Web/API Findings

The same 7-gate structure applies to web/API bug bounty findings with adapted terminology:

| Gate | Web/API Translation |
|------|-------------------|
| Code Reading | Read the actual HTTP response/JavaScript, not the API docs |
| Reachability | Map the exact request path from entry point to vulnerable handler |
| Threat Model | Who can send the request? Anonymous, authenticated user, admin? |
| Invariant Breach | What security boundary is crossed? (tenant isolation, authz, data ownership) |
| Protocol Intent | Is this behavior documented as intentional? Check changelog/design docs |
| Impact | What concrete harm? (PII exposure, ATO, financial loss, RCE) |
| Formal Proof | Working curl request that demonstrates the vulnerability |

---

## Integration with BountyForge's 7-Question Gate

BountyForge's native 7-Question Gate (SKILL.md PHASE 4) is the quick-kill version. Al-Mizaan is the deep-validation version. Use Al-Mizaan when:

- A finding passes the 7-Question Gate but feels borderline
- The finding involves complex protocol logic or multi-step attack chains
- You need to defend the finding against a skeptical triager
- The finding is in a smart contract audit context

The two frameworks are complementary:
- **7-Question Gate** = fast triage (30 seconds per finding)
- **Al-Mizaan v3** = deep validation (5-15 minutes per finding)

---

## Vulnerability Acceptance Rates (CC0 — Embedded)

Data from 1,032 exactly-reconciled findings across 10 Sherlock contests. Use for pre-hunt prioritization and post-hunt confidence calibration.

| Pattern | Rate | Accepted/Total | n | Use for Prioritization |
|---------|------|---------------|-----|----------------------|
| reentrancy | 78% | 40/51 | 51 | High priority — strong signal |
| overflow | 58% | 26/45 | 45 | High priority — moderate signal |
| trusted-actor | 51% | 159/311 | 311 | High priority — very strong sample |
| fee-miscalculation | 50% | 55/109 | 109 | Medium priority |
| staleness | 49% | 86/174 | 174 | Medium priority |
| mev-slippage | 49% | 44/89 | 89 | Medium priority |
| access-control | 47% | 35/74 | 74 | Medium priority |
| flash-loan | 46% | 6/13 | 13 | Low confidence (small n) |
| dos-griefing | 41% | 64/156 | 156 | Medium priority |
| rounding | 40% | 25/63 | 63 | Medium priority |
| oracle-manipulation | 36% | 47/131 | 131 | Medium priority — common, low hit rate |
| liquidation | 29% | 4/14 | 14 | Low confidence (small n) |

**How to use this data:**
- **Rate > 60%** → well-established pattern, reports in this class have high acceptance. Prioritize hunting.
- **Rate 40-60%** → moderate signal. Gate carefully — many submissions fail on impact or reachability.
- **Rate < 40%** → low acceptance. These bug classes have high false-positive rates. Require stronger PoC.
- **n < 20** → directional only. Not enough data for statistical confidence. Treat as rough signal.

**Limitations:** 10 of 105 contests reconciled. Tagging at ~65% precision. Measures submission reliability, not exploit frequency. Does not cover silent misses.

---

## MCP Server Integration

The full dataset and AI scanning are available as an MCP server. See `references/bug-bounty-intelligence-mcp.md` for setup and usage.

**Quick setup:**
```bash
claude mcp add bug-bounty-intelligence -- npx -y bug-bounty-intelligence-mcp@latest
```

**Tools:** `scan_contract` ($5 USDC, automated Solidity audit), `get_scan_report` (free), `list_vulnerability_patterns` (free, the rates above).

---

## Source & Credits

- **Repository:** [holistis/bug-bounty-intelligence-mcp](https://github.com/holistis/bug-bounty-intelligence-mcp)
- **MCP Server:** `npx -y bug-bounty-intelligence-mcp@latest` — npm package with 3 tools
- **Methodology:** `METHODOLOGY.md` — acceptance-rate derivation from exactly-reconciled Sherlock contest data
- **Benchmark:** `BENCHMARK.md` — 100% Slither false-positive rate on 3FLabs/grunt, demonstrating why scope-aware, context-aware analysis matters
- **Free dataset:** `vulnerability-acceptance-rates.json` — CC0-licensed, 1,032 verified findings across 10 contests
- **Sibling project:** [3ilm-mcp](https://github.com/holistis/3ilm-mcp) — free-only MCP server for vulnerability pattern lookup
