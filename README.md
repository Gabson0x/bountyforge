#  BountyForge

> All-round bug bounty skill for Claude Code — parallelized agents for smart contract audits (EVM, Move, Solana, TRON), web/API security, and submission-ready reports for HackerOne, Bugcrowd, Intigriti & Immunefi.

---

## What It Does

BountyForge spins up **8 specialized security agents in parallel**, each attacking a different surface of your target. Findings are deduplicated, gate-evaluated, CVSS-scored, and formatted into a submission-ready report — in minutes.

| Agent | Covers |
|---|---|
| Web / API | Auth bypass, IDOR, XSS, SSRF, SQLi, GraphQL, CORS |
| Smart Contract | EVM, Move/Aptos, Solana, TRON — structural & chain-specific bugs |
| Access Control | Role bypass, init hijack, confused deputy, proxy admin |
| Business Logic | State machine abuse, workflow skip, limit bypass, payment logic |
| Crypto / Math | Overflow, precision loss, signature replay, EIP-712, nonce issues |
| Race Conditions | Front-running, sandwich, TOCTOU, rotation window races |
| Economic Security | Flash loans, oracle manipulation, inflation attacks, DeFi tokenomics |
| Recon | Subdomain takeover, secret leaks, cloud misconfig, chain explorer recon |

**Supported chains:** Ethereum / EVM · Aptos / Move · Solana / Anchor · TRON

**Report formats:** HackerOne · Bugcrowd · Intigriti · Immunefi · Generic

---

## Installation

### Claude Code (terminal)

```bash
git clone https://github.com/Gabson0x/bountyforge.git ~/.claude/skills/bountyforge
```

Start a fresh Claude Code session — skills load at startup.

### Claude.ai (web/app)

1. Go to **Customize → Skills**
2. Make sure **Code execution** is enabled in **Settings → Capabilities**
3. Upload the `.skill` file from [Releases](https://github.com/Gabson0x/bountyforge/releases)

---

## Usage

### Audit a contract or repo

```
audit contracts/
```
```
run bountyforge on src/usdc.move --platform immunefi --cvss --file-output
```
```
check this contract for vulns --platform h1 --cvss
```

### Web / API target

```
bountyforge on https://api.target.com
```
```
find vulns in this API — [paste endpoints / Swagger / JS bundle]
```

### Generate a report from findings

```
write a HackerOne report for this finding: [paste notes]
```
```
generate immunefi report --cvss: [describe the vuln]
```

---

## Flags

| Flag | Description |
|---|---|
| `--platform h1` | Format output for HackerOne |
| `--platform immunefi` | Immunefi template |
| `--platform bugcrowd` | Bugcrowd format |
| `--platform intigriti` | Intigriti format |
| `--cvss` | Include full CVSS 3.1 vector string + justification |
| `--file-output` | Save report to `bountyforge-report-[timestamp].md` |
| `--full` | Run all 8 agents regardless of detected file type |

---

## How It Works

```
Discover files / scope
        ↓
Build agent bundles (source + agent instructions)
        ↓
Spawn 8 agents in parallel
        ↓
Deduplicate findings by (Target | location | bug-class)
        ↓
Gate evaluation: Refutation → Reachability → Trigger → Impact
        ↓
CVSS 3.1 scoring
        ↓
Submission-ready report
```

Every finding passes four gates before it's confirmed:

1. **Refutation** — can the attack be concretely blocked by an existing guard?
2. **Reachability** — can the vulnerable state exist in a live deployment?
3. **Trigger** — can an unprivileged actor execute it profitably?
4. **Impact** — is there material harm to an identifiable victim?

Fail any gate → rejected or demoted to a lead for manual review.

---

## Tips

- **Target hot contracts.** Point BountyForge at the 2–5 files you're actively reviewing rather than an entire repo. Smaller scope = denser context per agent = higher-signal findings.
- **Run more than once.** LLM output is non-deterministic — each run can surface different vulnerabilities. Two or three passes often catch what a single pass misses.
- **Chain findings.** BountyForge automatically detects composite chains (e.g., auth bypass → privilege escalation) and reports them as a combined severity.
- **Use `--file-output`** when submitting. It saves a clean markdown report you can paste directly into the platform.

---

## Updating

```bash
cd ~/.claude/skills/bountyforge
git pull
```

BountyForge checks for updates automatically on each run and will warn you if a newer version is available.

---

## Structure

```
bountyforge/
├── SKILL.md                          # Main orchestrator
├── VERSION                           # Current version
└── references/
    ├── judging.md                    # 4-gate evaluation rules
    ├── report-formatting.md          # Platform report templates
    ├── cvss-guide.md                 # CVSS 3.1 scoring guide
    ├── attack-vectors/
    │   ├── web-api-vectors.md
    │   ├── smart-contract-vectors.md
    │   └── business-logic-vectors.md
    └── hacking-agents/
        ├── shared-rules.md
        ├── web-api-agent.md
        ├── smart-contract-agent.md
        ├── access-control-agent.md
        ├── business-logic-agent.md
        ├── crypto-math-agent.md
        ├── race-condition-agent.md
        ├── economic-security-agent.md
        └── recon-agent.md
```

---

## Disclaimer

BountyForge is intended for authorized security research and bug bounty programs only. Only use it against targets you have explicit permission to test. The author is not responsible for misuse.

---

Built by [@Gabson0x](https://github.com/Gabson0x) · [Synq Studio](https://github.com/synqstudio)