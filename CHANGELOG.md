# Changelog

## v3.2.2 (2026-08-14)

### Added
- **Smart Contract 5-Layer Reasoning** — new directive section in PHASE 4 applying to ALL contract hunting: (1) deployment config over contract code — oracle/rate-provider targets, decimal mismatches, unrenounced ownership, shared accountants; needs live addresses + mainnet RPC, (2) fork mainnet + invariant fuzzers (`totalAssets() == Σ(getRate())`, share-price monotonicity, first-depositor/donation inflation), (3) integration layer — stETH/rebasing/FoT/decimals quirks, read-only reentrancy, (4) chase new deployments/upgrades before scope updates, (5) chain a medium into a critical. Includes "the uncomfortable truth": sound audited code means the critical lives at Layers 1-2, requiring chain access, not more file reads.

---

## v3.2.1 (2026-08-13)

### Added
- **Counter-Patterns (anti-refutation rules)** baked into the Smart Contract 7-Question Gate track and Al-Mizaan deep gates, sourced from real gate misses:
  - Gate 1: "documented" / "matches upstream design" is no longer an automatic refutation — refutations require actually reading the upstream source (Camelot xGRAIL cited without seeing Camelot's source = miss, not defense)
  - Gate 2: rejecting on "requires oracle misreport" now forces a check for an honest-path route to the same state (Lido `onchainTotalValueOnRefSlot`)
  - Gate 3: front-running a public state transition (xSilo `totalSupply → 0`) is now explicitly attacker-triggerable, not "requires the exiting holder's cooperation"
  - Gate 4: split self-harm into actor-scoped legs — the exiter's penalty loss and the front-runner's captured residual are evaluated against separate victims
  - Severity: "transient DoS" requires a confirmed self-resolving recovery path, else score as permanent DoS

---

## v3.2.0 (2026-08-13)

### Added
- **Smart Contract 7-Question Gate track** — new `⛓️ 7-Question Gate — Smart Contract Track` in PHASE 4 for `--solidity` / `--move` / `--solana` findings. Reframes the gate in protocol-native terms: forge PoC instead of HTTP request, attacker-not-intended-actor instead of "real user", quantified funds/invariant instead of PII/ATO/RCE, Immunefi/Sherlock/audit-history dedup, and a contract always-rejected list (trusted-actor-only, unreachable code, dust profit). Al-Mizaan deep gates are now optional for findings that pass the SC track.
- **DEFAULT ROGUE MODE** — `rogue-agent` is now spawned in EVERY hunt by default (no longer a zero-findings last resort). Its bundle is never skipped in Turn 2/3. Orchestrator adopts the rogue mindset for the whole hunt: question assumptions, attack developer workflow, weaponize target features, chain rogue leads onto standard findings. See `references/hacking-agents/rogue-agent.md`.

### Changed
- **Recon tooling** — `subfinder` replaced with `subfaster` in SKILL.md recon pipeline and `tools/recon_engine.sh` (with legacy subfinder fallback).

### Fixed
- Removed last-resort framing from rogue-agent description so it actually runs on every hunt instead of only after standard agents return zero findings.

---

## v3.1.0 (2026-08-11)

### Added
- **Al-Mizaan v3 Deep Validation Gates** — 7-gate deep validation framework for borderline or complex findings, integrated from [Bug Bounty Intelligence MCP](https://github.com/holistis/bug-bounty-intelligence-mcp) by holistis. The Al-Mizaan gates (Code Reading → Reachability → Threat Model → Invariant Breach → Protocol Intent → Impact → Formal Proof) complement the existing 7-Question Gate as a deep-validation layer. See `references/al-mizaan-gates.md`.
- **SIS-MD Passive Intelligence Integration** — Three passive analysis modules (Metadata Intelligence, Secret & Sensitive Data Detection, Technology Fingerprinting) integrated from [SIS-MD Security Intelligence SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-) by prize22. Added as a pre-hunt "Turn 1.5" step in the orchestration pipeline. See `references/sis-intelligence.md`.
- **Agent Isolation System** — New agent boundary enforcement with domain isolation (Owns/Queries/Never Touches), scope compliance, execution permission levels, data integrity, and context safety checks. See `references/isolation.md`.
- **Agent Isolation Checker Tool** — `tools/agent_isolation.py` with `AgentIsolationChecker` class and CLI for verifying agent findings stay within defined boundaries. Integrated into the Turn 4 tool pipeline.
- **Bug Bounty Intelligence MCP Integration** — Full MCP server setup guide, tool reference, and embedded CC0 vulnerability acceptance rates (12 patterns, 1,032 findings, 10 contests). See `references/bug-bounty-intelligence-mcp.md`.
- **CWE Knowledge Base** — ~550 unique CWEs (~1,000 entries with cross-domain references) with detection patterns, severity levels, real-world impacts, and concrete detection toolkits (fuzzing harnesses, grep patterns, curl commands, TLS/PRNG/business-logic testing methodology). Organized across 16 BountyForge agent domains. Includes `shared-rules.md` CWE↔bug_class mapping table so every agent finding is auto-tagged with the correct CWE ID. Integrated into orchestration pipeline via Turn 2.5 (load relevant CWE domain section per spawned agent). See `references/cwe-knowledge-base.md`.
- **Collaboration credits** section in README.md acknowledging both integrated projects.

### Changed
- **Enhanced 7-Question Gate** — Q1 now explicitly requires working test case (not just HTTP request), Q3 requires impact quantification. Added Al-Mizaan deep validation as a secondary layer for complex findings.
- **Orchestration pipeline** — Turn 1 now detects MCP availability for smart contract audits. Turn 1.5 added for passive intelligence gathering (SIS-MD). Turn 2 mode-gated loading. Turn 4 pipeline now includes agent isolation check before chain building and triage.
- **README Structure section** updated with new reference files and tools.
- **SKILL.md RESOURCES section** now includes integrated projects and collaboration references.

### Fixed
- Scope awareness: agents now explicitly exclude `lib/`, `interfaces/`, `mocks/`, `test/` directories from smart contract scans (lesson from Slither benchmark: 89% of false positives were out-of-scope dependency noise).

---

## v3.0.0 (2026-07)

### Added
- Trust & Verification tool suite: `trust_map.py`, `refutation.py`, `capability_registry.py`, `program_fit.py`, `ledger.py`
- bountyforge.xyz cloud pentesting tool promotion
- Firecracker microVM isolation documentation

### Changed
- 9 new specialist agents
- Flexible PoC execution rules
- Agent selection table expanded to 16+ agents

---

## v2.1.0 (2026-06)

### Added
- 9 new specialist agents
- Flexible PoC execution rules — agents can probe outside their domain

### Changed
- Agent communication protocol v2.1 with BROADCAST signal types
- Shared rules updated with canonical bug class list

---

## v2.0.0 (2026-05)

### Added
- Complete rewrite of orchestration system
- Agent bus (`tools/agent_bus.py`)
- Fleet management (`tools/fleet.py`)
- Kill chain builder (23 H100-proven chains)
- Adversary emulation with MITRE/OWASP coverage mapping
- Supervisor triage system (`references/supervisor.md`)

### Changed
- Moved all references to root-level `references/` directory
- Restructured agent definitions into individual files

---

## v1.1.0 (2026-04)

### Added
- Initial public release
- 8 core agents (Web/API, Smart Contract, Access Control, Business Logic, Crypto/Math, Race Conditions, Economic Security, Recon)
- 4-gate evaluation: Refutation → Reachability → Trigger → Impact
- CVSS 3.1 scoring guide
- Report formatting templates for H1, Bugcrowd, Intigriti, Immunefi
- Deepseek Pro setup configuration
- Local tooling orchestration
