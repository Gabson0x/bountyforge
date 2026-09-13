# Release Notes

## v4.0.0 — All Skills Wired (2026-09-13)

**Major release.** BountyForge is now a self-contained, fully-wired autonomous security auditor with 17 bundled skills, 9 new modes, and 59,000+ lines of integrated domain knowledge.

### What Changed

**17 Skills Bundled** — The repo is now self-contained. All external skills live in `skills/`:

| Skill | Domain |
|-------|--------|
| `bb-methodology` | 5-phase workflow + 4 thinking domains |
| `bug-bounty` | Full BB workflow with chain hunting |
| `code-sleuth` | EVM storage-safety analysis |
| `fizz` | Echidna/Medusa fuzz suite generation (11-step pipeline) |
| `godmod` | 4-persona expert mode |
| `hackenproof-triage-marketplace` | HackenProof triage workflow |
| `meme-coin-audit` | Rug pull detection (8 token bug classes) |
| `pashov/solidity-auditor` | 12 parallel Solidity audit agents |
| `pashov/x-ray` | Pre-audit x-ray report |
| `report-writing` | Platform-specific report templates |
| `security-arsenal` | Payload library + bypass tables |
| `smart-contract-audit` | 7 blockchain platforms (EVM, Solana, TON, Sui, Cosmos, Near, Cardano) |
| `triage-validation` | 7-Question Gate with SC track |
| `web2-recon` | Full web2 recon pipeline |
| `web2-vuln-classes` | 28 bug classes with bypass tables |
| `web3/*` | 11 Web3 sub-skills (grep arsenal, PoC Foundry, bug classes, triage, etc.) |
| `web3-audit` | 10 DeFi bug classes with 5-layer reasoning |

**9 New Modes:**

| Mode | Purpose |
|------|---------|
| `--web3` | Full Web3 smart contract + protocol audit |
| `--fuzz` | Fuzz suite generation (Echidna/Medusa) |
| `--multi-chain` | Multi-blockchain audit (7 platforms) |
| `--xray` | Pre-audit x-ray report with threat model |
| `--solidity-audit` | 12-agent parallel Solidity deep audit |
| `--meme` | Meme coin / token security audit |
| `--storage` | EVM storage-safety analysis |
| `--hackenproof` | HackenProof triage workflow |
| `--expert` | Godmod expert mode (4 personas) |

**New Inline Content in SKILL.md:**

- **Multi-chain support** — 7 blockchain platforms with three-layer reading order and protocol-specific audit tricks
- **Web3 grep arsenal** — 3-tier copy-paste grep blocks for first 30 minutes of any new Solidity target
- **10 attacker questions** — For every external smart contract function
- **Godmod expert mode** — 4 simultaneous personas (Security Researcher, Pentester, Senior Dev, Cracked Generalist)
- **Fuzz suite generation** — 11-step pipeline with 5 specialized invariant discovery agents
- **X-ray pre-audit** — Enhanced threat model with git-weighted attack surfaces, composability mapping
- **Meme coin audit** — 8 token-specific bug classes, Solana SPL checks, Token-2022 extension risks
- **Storage-safety analysis** — Lost writes, proxy collisions, attacker-influenced storage slots
- **HackenProof triage** — Mandatory tool sequence, 4 pre-validation gates, decision states
- **Immunefi Web3 triage** — 20 real paid bounty patterns dissected
- **MFA bypass** — 7 patterns with testing checklist
- **SAML attacks** — XSW, comment injection, signature stripping
- **XXE, deserialization, host header injection, custom header injection, WebSocket attacks**
- **Agentic AI vectors** — ASI01-ASI10 in practice (chatbot IDOR, prompt injection, indirect injection)

### Breaking Changes

- Skills are now loaded from `skills/` directory (local paths) instead of `~/.claude/skills/`
- VERSION bumped from 3.3.5 to 4.0.0

### Stats

- 493 files changed
- 59,324 lines added
- 17 skills bundled
- 9 new modes
- 10+ new inline reference sections

---

## v3.4.1 (2026-08-17)

### Added
- **THE TWO-QUESTION RULE — Trigger x Impact** — fixes premature-kill failure mode
- **Smart Contract 7-Question Gate** — separate gate for DeFi/contract findings
- **Counter-patterns** — documented refutations requiring upstream code verification

## v3.4.0 (2026-08-21)

### Added
- Adversarial Refutation Engine Upgrade
- Exploit Generator with Absent Credential Evidence Grid
- Program Fit Multi-Context Support
- Persistent Lead Ledger Tripwires
- Cloud Sandbox & Agentic AI attack vector references

## v3.3.3 (2026-08-20)

### Added
- Platform-Hosted Product Hunting (PHP) module
- Scoping-Order Analysis
- Scope-Text Re-Derivation Gate
- Dismissed-Lead Ledger with Re-Trigger Conditions
- Abandonment Discipline
