# Changelog

## v3.1.0 (2026-08-11)

### Added
- **Al-Mizaan v3 Deep Validation Gates** — 7-gate deep validation framework for borderline or complex findings, integrated from [Bug Bounty Intelligence MCP](https://github.com/holistis/bug-bounty-intelligence-mcp) by holistis. The Al-Mizaan gates (Code Reading → Reachability → Threat Model → Invariant Breach → Protocol Intent → Impact → Formal Proof) complement the existing 7-Question Gate as a deep-validation layer. See `references/al-mizaan-gates.md`.
- **SIS-MD Passive Intelligence Integration** — Three passive analysis modules (Metadata Intelligence, Secret & Sensitive Data Detection, Technology Fingerprinting) integrated from [SIS-MD Security Intelligence SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-) by prize22. Added as a pre-hunt "Turn 1.5" step in the orchestration pipeline. See `references/sis-intelligence.md`.
- **Agent Isolation System** — New agent boundary enforcement with domain isolation (Owns/Queries/Never Touches), scope compliance, execution permission levels, data integrity, and context safety checks. See `references/isolation.md`.
- **Agent Isolation Checker Tool** — `tools/agent_isolation.py` with `AgentIsolationChecker` class and CLI for verifying agent findings stay within defined boundaries. Integrated into the Turn 4 tool pipeline.
- **Bug Bounty Intelligence MCP Integration** — Full MCP server setup guide, tool reference, and embedded CC0 vulnerability acceptance rates (12 patterns, 1,032 findings, 10 contests). See `references/bug-bounty-intelligence-mcp.md`.
- **CWE Knowledge Base** — 1,047 CWEs with detection patterns, severity levels, and real-world impacts organized across 16 BountyForge agent domains (Web/API Injection, XSS, SSRF, Auth/Session, Authorization, Crypto, Business Logic, Race Conditions, Information Leakage, Smart Contracts + SWC registry, Network/Infrastructure, CI/CD/Supply Chain, Mobile, Cloud/Container, GraphQL, HTTP Smuggling/Cache Poisoning). Includes agent-to-CWE quick index. See `references/cwe-knowledge-base.md`.
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
