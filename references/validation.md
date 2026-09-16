# Validation — Smart-Contract Reasoning, 7-Question Gate, Triage

> Split from SKILL.md v4.1.0. Load before writing ANY report. Compact gate: `skills/triage-validation/SKILL.md`. Supervisor detail: `references/supervisor.md`.

---

# PHASE 4: VALIDATE

## SMART CONTRACT REASONING — 5-LAYER PRIORITY (applies to ALL contract hunting, before any gate)

**First: map the protocol and write `invariants.md` (Rule 1).** Before any layer below, list the protocol's solvency/supply/permission/price invariants and run the economic loop — `MAP → INVARIANT → IDENTIFY ASSUMPTION → FIND CONTROLLED VARIABLE → MUTATE → OBSERVE → CHECK INVARIANT → CHAIN → CALCULATE VALUE AT RISK` (full track: `references/methodology.md` — Smart-Contract Track). Every finding names the invariant it breaks and the value it puts at risk.

The criticals on audited code are rarely in the code. Rank effort by where bugs actually live:

**Layer 1 — Deployment config, not contract code (biggest source of criticals on audited code).** The invariant is enforced in Solidity but violated at deploy time:
- Rate provider / oracle pointed at a manipulatable spot price (Curve pool, short-window Uniswap TWAP, Balancer pool) instead of Chainlink → exchange rate manipulation → share-price theft
- Decimal mismatch: rate provider returns 6 decimals where the accountant assumes 18 (10^12 error). Scaling helpers (e.g., `GenericRateProviderWithDecimalScaling`) only scale if `inputDecimals`/`outputDecimals` are set correctly at deploy
- Ownership not actually renounced (`transferOwnership(address(0))` skipped), or `STRATEGIST_ROLE` held by a hot EOA
- Two vaults sharing one accountant; a `manageRoot` computed against a stale decoder
- **You CANNOT see this from source. It needs the live addresses + mainnet RPC.** When the code reads clean, request the deploy addresses and fork the chain — that IS the attack surface.

**Layer 2 — Fork mainnet and run invariant fuzzers.** Criticals are found by simulating the state machine against live state (Foundry fork tests + `invariant_` fuzzing), not by more reading. Core invariants:
- `totalAssets() == Σ(balances valued via getRate())` — break this → mint/drain
- Share price monotonicity across deposit/withdraw/vest/postLoss sequences
- First-depositor / donation inflation: `mulDivDown(ONE_SHARE, getRate())`; a donation or `claimFees` timing that shifts `getRate()` between enter and exit = classic repeatable-loss critical

**Layer 3 — The integration layer, not the target.** The vault holds real tokens with real quirks; a decoder correct for the "canonical" ABI is wrong for the deployed variant:
- stETH / rebasing / fee-on-transfer / 18-vs-6 tokens where a balance read or transfer assumption breaks
- A token that's a proxy with different `decimals()`, or a token with a `beforeTokenTransfer` hook that re-enters
- Read-only reentrancy via `getRate()` reading an external contract whose state can be manipulated in the same tx

**Layer 4 — Chase new deployments and upgrades.** Protocols add tellers/decoders/adapters continuously; the newly added, unaudited contract is where the critical lives. A hardened adapter (fee/extension bounds added post-finding) means the NEXT one won't be. Watch the deployer address for fresh contracts and audit them before the program updates scope.

**Layer 5 — Chain a medium into a critical.** A single small bug is a Medium; the same bug made repeatable is a Critical. A 1-wei accounting drift in `payoutSplits` (balance - 1) or a rounding direction in `mulDivDown` compounded over N deposits becomes an extractable loss.

**The uncomfortable truth:** if the audited code is sound, the critical is at Layer 1 (config/oracle targets) or Layer 2 (fork-fuzzing `getRate()` against a manipulatable feed) — both need live chain access, not more file reads. When file reads run dry: request deployment addresses + RPC, fork, and fuzz. That's not a limitation; that's the attack surface.

---

## The 7-Question Gate & Red Team Triage Engine (Run BEFORE Writing ANY Report)

> **HUNT vs REPORT (wild mode):** These gates are the LAST step of the pipeline — they filter what gets SUBMITTED. They are never run during the hunt, never kill a probe, and never delete a lead. A finding that fails a gate is demoted to a LEAD with its payload and its chain partners, and retested on the next pass. **Firing a payload is always allowed; the gates only decide what a human triager reads.**
>
> **5-STEP METHODOLOGY SPINE:** `Program policy → Scope → Security boundary → Demonstrated impact → Severity`
>
> **RED TEAM TRIAGE ENGINE:** Before drafting a report, apply `references/supervisor.md` — BountyForge attacks its own finding across **10 Red Team Attack Questions**:
> 1. *Scope:* Is the exact asset/function in scope?
> 2. *Policy:* Is this vulnerability class explicitly excluded?
> 3. *Precondition:* What does the attacker actually need?
> 4. *Authentication:* What credential/authorization is supposed to exist?
> 5. *Path A:* What is the legitimate intended flow?
> 6. *Path B:* What unauthorized flow was demonstrated?
> 7. *Boundary:* What security boundary is crossed?
> 8. *Impact:* What concrete capability does the attacker gain?
> 9. *Alternative explanation:* What is the strongest reasonable triager rebuttal?
> 10. *Evidence:* What observation defeats that rebuttal?
>
> **THE RED TEAM RULE:** If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report.
>
> **DEMONSTRATED VS INFERRED RULE:** Explicitly categorize every claim as **Demonstrated** (verified via executed PoC), **Inferred** (suggested by code/arch but unexecuted), or **Unproven** (speculative). Never allow report drift from a demonstrated primitive to an unproven claim (e.g. guest execution primitive drifting into unproven host escape).

All 7 must be YES. Any NO → STOP. See also `references/supervisor.md` for detailed triage flow and `references/al-mizaan-gates.md` for deep validation methodology.

### Q1: Can I exploit this RIGHT NOW with a real PoC?
Write the exact HTTP request or test case. If you cannot produce a working trigger → KILL IT.

### Q2: Does it affect a REAL user who took NO unusual actions?
No "the user would need to..." with 5 preconditions. Victim did nothing special.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is not impact. "I read victim's SSN" is impact. Quantify the harm.

### Q4: Is this in scope per the program policy?
Check the exact domain/endpoint against the program's scope page.

### Q5: Did I check Hacktivity/changelog for duplicates?
Search the program's disclosed reports and recent changelog entries.

### Q6: Is this NOT on the "always rejected" list?
Check the list below. If it's there and you can't chain it → KILL IT.

### Q7: Would a triager reading this say "yes, that's a real bug"?
Read your report as if you're a tired triager at 5pm on a Friday. Does it pass?

---

### ⛓️ 7-Question Gate — Smart Contract Track (USE FOR ALL CONTRACT FINDINGS)

The web2 gate kills good contract bugs — "real user", "PII/ATO/RCE" don't translate to a DeFi protocol. For `--solidity` / `--move` / `--solana` findings, run THIS gate instead. All 7 must be YES. If a finding passes, the Al-Mizaan deep gates below are optional, not required.

### Q1 (SC): Can I exploit this RIGHT NOW with a working PoC?
Write a running Foundry/Hardhat test (or fork script) that triggers the path and asserts the damage. Static code observation, "this line looks wrong", or unexecuted speculation → KILL IT. PoC must execute against a fork of the deployed chain or a local EVM node.

**Counter-pattern (Gate 1):** "It's documented" / "it matches upstream design" is NOT an automatic refutation. Rejecting on that requires actually having read the upstream source — citing another protocol's behavior without seeing its code (e.g., "Camelot does the same with xGRAIL") is a miss, not a defense. Docs describe intent; deployed bytecode is reality. If you reject on documentation, show the upstream code doing the same thing.

### Q2 (SC): Is the triggerer someone the protocol does NOT intend to be the actor?
Ask: "Who does the protocol DESIGN to call this?" If only `onlyOwner`/governance/`onlyRole` can trigger it and it's working as designed → intended, KILL. If ANY other party (user, third-party contract, griefer, LP depositor) can reach the vulnerable path — even with clever conditions — it's valid. Trusted-actor trigger WITH a governance bypass still passes.

**Counter-pattern (Gate 2):** "Requires an oracle misreport" is NOT an auto-kill. Before rejecting, check for an honest-path route to the same vulnerable state (e.g., the Lido `onchainTotalValueOnRefSlot` case — the state was reachable with HONEST oracle data, making the "oracle manipulation" precondition unnecessary). If an honest path exists, the finding stands without the oracle caveat.

**Counter-pattern (Gate 3):** "Requires the exiting holder's cooperation" is NOT an auto-kill when the state transition is public and observable on-chain (e.g., an xSilo `totalSupply → 0` after exit). The attacker can front-run the public transition — that makes it attacker-triggerable, not victim-cooperative. Precondition = a transaction the victim will unavoidably submit, not a deliberate action on their part.

### Q3 (SC): Is impact concrete in protocol-native terms?
"Technically possible" is not impact. Quantify: exact funds stolen/locked (wei, token amounts, USD), accounting desync amount, invariant breach (name the invariant verbatim from the code/docs), permanent DoS of someone's funds, oracle manipulation with real profit margin. No number = no finding.

**Counter-pattern (Gate 4):** Split self-harm into actor-scoped legs. An attack that looks like "self-harm" often has SEPARATE victims per leg: the exiter's penalty loss is evaluated as its own leg, and the front-runner's captured residual is another leg — one leg being self-inflicted does NOT kill the other leg's valid impact. Name the victim for every leg before rejecting as "self-harm."

### Q4 (SC): Is this in scope per the program policy?
Deployed contract on the listed chain, and the exact version verified on-chain (etherscan/solscan match the audited source). Testnets, old unpinned versions, `interfaces/`, `lib/`, `mocks/`, `*.t.sol`, `*Mock*` → KILL.

### Q5 (SC): Did I check known-issue history for duplicates?
Search: Immunefi/Sherlock/Code4rena contest history for this protocol, ALL prior audit reports (in the repo's `audits/` or docs), `CHANGELOG.md`, README "known issues" sections, and previous bounty submissions. Duplicate → KILL.

### Q6 (SC): Is this NOT on the contract always-rejected list?
- Theoretical / no working PoC → KILL
- Trusted-actor-only with no bypass → KILL
- View/read-only fn returning wrong value with no downstream effect → KILL
- Admin backdoor behaving as documented → KILL
- MEV-dependence the protocol explicitly accepts (e.g., sandwichable AMMs) → KILL unless the profit exceeds documented slippage bounds
- Sub-$1 dust profit that breaks no invariant → KILL (unless part of a bigger chain)

### Q7 (SC): Would a DeFi-literate judge say "yes, that's a real bug"?
Read it as an Immunefi/Sherlock judge: quote the invariant, trace the exact exploitable call path, show the PoC result. If the judge could argue "edge case, working as intended" and you can't pre-kill that argument → KILL.

**Smart contract quick-kill rules (before you even write the report):**
- No `forge test` PoC against a fork → DEMOTE to lead, not a finding
- Trigger only via `onlyOwner`/governance → KILL unless you have a governance bypass
- Code in `lib/`, `interfaces/`, `mocks/`, `test/` → KILL (scanner noise)
- "Docs say X but code does Y" → code is authoritative, report the code behavior
- Compiler version is old but function unreachable → KILL (reachability before severity)
- **Trigger proven but impact untraced → OPEN LEAD, not KILL.** "No attacker profit" refutes nothing — an accounting desync that strands or misdirects account value is account-owner loss, a Medium floor on Immunefi on its own. Trace the harm before any severity call (Two-Question Rule).

**Severity rule — "transient DoS" is only valid if it self-resolves:**
Never call something a "transient DoS" without confirming the recovery path actually exists and executes on its own (a timelock that expires, a keeper that is guaranteed to run, a function any user can call to restore). If recovery depends on an action a specific party may never take, or on conditions you have not verified, score it as permanent DoS (or drop it if no DoS is provable). Assumed recovery = inflated severity.

---

### Deep Validation: Al-Mizaan v3 Gates (for borderline or complex findings) ⚡ On-Demand

The 7 gates below are self-contained. **Do NOT load `references/al-mizaan-gates.md` unless you need the full methodology with web/API translations and Sherlock contest evidence.** Use this inline version for 95% of cases.

When a finding passes the 7-Question Gate but feels borderline, involves complex protocol logic, multi-step attack chains, or smart contract context:

1. **Code Reading** — Does the code actually execute the vulnerable path? (Not docs, not comments)
2. **Reachability Chain** — Map the exact call path from external entry point to vulnerable operation
3. **Threat Model** — Who can trigger it? Trusted actor only with no bypass? → ELIMINATE. **Counter-patterns:** "requires oracle misreport" ≠ auto-kill — check for an honest-path route to the same state (Lido `onchainTotalValueOnRefSlot`). "Requires victim cooperation" ≠ auto-kill — a public on-chain state transition (e.g., xSilo `totalSupply → 0`) is front-runnable and therefore attacker-triggerable.
4. **Invariant Breach** — What protocol security property is violated?
5. **Protocol Intent** — Would the designers call this a bug or a feature? **Counter-pattern:** "documented" / "matches upstream design" refutations require actually reading the upstream source — citing another protocol (e.g., "Camelot does the same with xGRAIL") without seeing its code is a miss, not a defense. Verify upstream bytecode before rejecting.
6. **Impact** — Quantify concrete harm in native terms (exact amount, not "could be significant"). **Counter-pattern:** split self-harm into actor-scoped legs — the exiter's penalty loss and a front-runner's captured residual are SEPARATE victims; one self-inflicted leg does not kill the other leg's impact. **Severity:** "transient DoS" requires a confirmed self-resolving recovery path, else score as permanent DoS.
7. **Formal Proof** — Working PoC that executes against a realistic environment

**Quick kill rules (from Al-Mizaan + Slither benchmark lesson):**
- Trusted-actor-only trigger with no governance bypass → ELIMINATE
- Finding in `lib/`, `interfaces/`, `mocks/`, `test/` → ELIMINATE (89% of automated scanner "Highs" are out-of-scope dependency noise)
- No working PoC against realistic environment → DEMOTE to LEAD
- "Documentation says X but code does Y" → code is authoritative, report the code behavior

**Load the full `references/al-mizaan-gates.md` only when:**
- The finding involves complex DeFi protocol economics
- You need the Sherlock contest acceptance-rate data to defend severity
- A triager is pushing back and you need the formal methodology citation

## 4 Pre-Submission Gates (from supervisor.md)

### Gate 0: Reality Check (30 seconds)
```
[ ] The bug is real — confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope — checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

---

## HackenProof Triage Workflow

When `--hackenproof` flag is set, apply HackenProof-specific triage pipeline:

### Mandatory Tool Sequence
1. `get_program_info` — Program scope, rules, severity definitions
2. `get_report_details` — Full report content, attachments
3. `get_attachments` — List all attachments
4. `fetch_attachment` — Download specific attachment content
5. `list_reports` — Search for similar/duplicate reports
6. `search_comments` — Check for prior triage discussion
7. `get_comments` — Read existing decision history

### 4 Pre-Validation Gates
1. **Commit/Version Match:** Does the report reference a specific commit/version? Verify it against deployed code.
2. **Scope Match:** Is the exact asset/function in the program's scope?
3. **Duplicate Check:** Search all reports for same vulnerability class + same endpoint
4. **PoC Presence:** Does the report include a working proof of concept?

### Decision States
| State | When |
|-------|------|
| **Out of Scope** | Asset/class not in program scope |
| **Duplicate** | Same vuln already reported |
| **Informative** | Valid finding but low/no security impact |
| **Not Applicable** | Claim cannot be reproduced |
| **Triaged** | Valid finding, passed all gates, ready for fix |

---

## Immunefi Web3 Triage (Smart Contract Track)

When reporting to Immunefi, apply these additional Web3-specific gates:

### 20 Real Paid Bounty Patterns (Dissected)

| # | Protocol | Bug Class | Payout | Key Lesson |
|---|----------|-----------|--------|------------|
| 1 | Beanstalk | Governance | $182M | Flash loan + governance = total drain |
| 2 | Cream Finance | Reentrancy | $130M | Cross-contract reentrancy via ERC777 |
| 3 | Pancake Bunny | Flash Loan | $45M | Price manipulation in same tx |
| 4 | Bondly Finance | Access Control | $1.6M | `setDefaultAdmin` callable by anyone |
| 5 | SushiSwap | Access Control | $3M | Migrator contract had unchecked owner |
| 6 | ValueDeFi | Flash Loan | $6M | Vault share price manipulation |
| 7 | Harvest Finance | Flash Loan | $34M | Price oracle manipulation via deposit |
| 8 | Curve Finance | Reentrancy | $62M | Vyper reentrancy via struct storage |
| 9 | Euler Finance | Access Control | $197M | Donate + liquidate = protocol insolvency |
| 10 | Platypus Finance | Access Control | $8.5M | Single-sided LP lock bypass |
| 11 | Decurra Protocol | Reentrancy | $1.6M | Staking contract reentrancy |
| 12 | Sentiment | Access Control | $1M | Arbitrary call via account abstraction |
| 13 | dYdX | Accounting | $2M | Margin trading accounting desync |
| 14 | Perp Protocol | Accounting | $5.5M | Funding rate calculation error |
| 15 | Moonwell | Access Control | $11.5M | Governance proposal exploit |
| 16 | Exactly Protocol | Access Control | $12M | Oracle manipulation + borrow |
| 17 |oki dEX | Access Control | $3M | Admin key compromise |
| 18 | CoinEx | Access Control | $70M | Hot wallet key leak |
| 19 | StakeWise | Flash Loan | $75M | MEV-Boost relay manipulation |
| 20 | Polycat Finance | Flash Loan | $1.2M | Mint + dump via price oracle lag |

### Immunefi Report Format Requirements
- **Asset Type:** Token, Chain, Smart Contract, etc.
- **Blockchain/Tech Stack:** Ethereum, BSC, Polygon, etc.
- **Vulnerability Category:** Access Control, Reentrancy, etc.
- **Root Cause:** Exact function and line number
- **Impact:** Exact funds at risk, not "could be exploited"
- **PoC:** Runnable Foundry test, not pseudocode
- **Recommended Fix:** One concrete fix, not "add access control"

## CVSS 3.1 Quick Guide

| Score | Severity | Typical Bug |
|-------|----------|-------------|
| 0-3.9 | Low | Info disclosure (non-sensitive) |
| 4-6.9 | Medium | IDOR (read PII), Stored XSS (low impact) |
| 7-8.9 | High | IDOR (write/delete), SQLi, Race (double spend) |
| 9-10 | Critical | Auth bypass → admin, SSRF (cloud metadata), RCE |

---

