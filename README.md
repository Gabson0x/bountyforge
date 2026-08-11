  
# bountyforge

> All-round bug bounty skill for Claude Code — parallelized agents for smart contract audits (EVM, Move, Solana, TRON), web/API security, local tooling orchestration, and submission-ready reports for HackerOne, Bugcrowd, Intigriti & Immunefi.

> **AI Pentesting Tool:** Run isolated, cloud-hosted pentesting sandboxes at **[bountyforge.xyz](https://bountyforge.xyz)** — your AI key, your Firecracker microVM, your report. Pipeline: recon → hunt → triage → H1-ready report. AI slop gets you rate-limited; BountyForge gets you paid.

> **New in v3.1.0:** Al-Mizaan v3 deep validation gates, SIS-MD passive intelligence integration, agent isolation checks. See [CHANGELOG.md](CHANGELOG.md).

---

## What It Does

Bounty Forge spins up **8 specialized security agents in parallel**, each attacking a different surface of your target. Findings are deduplicated, gate-evaluated, CVSS-scored, and formatted into a submission-ready report — in minutes.

| Agent | Covers |
|---|---|
| Web / API | Auth bypass, IDOR, XSS, SSRF, SQLi, CSV injection, open redirect, path traversal, parameter pollution, GraphQL, CORS |
| Smart Contract | EVM, Move/Aptos, Solana, TRON — structural & chain-specific bugs |
| Access Control | Role bypass, init hijack, confused deputy, proxy admin |
| Business Logic | State machine abuse, workflow skip, limit bypass, payment logic |
| Crypto / Math | Overflow, precision loss, signature replay, EIP-712, nonce issues |
| Race Conditions | Front-running, sandwich, TOCTOU, rotation window races |
| Economic Security | Flash loans, oracle manipulation, inflation attacks, DeFi tokenomics |
| Recon | Subdomain takeover, secret leaks, cloud misconfig, chain explorer recon |

**Supported targets:** web/API, smart contracts, infrastructure, supply chain, internal tooling, binary analysis

**Local tooling:** When Claude Code execution is enabled, BountyForge can orchestrate local CLI tools like `nmap`, `ffuf`, `amass`, `sqlmap`, `gobuster`, `curl`, `httpx`, `wfuzz`, `zap`, `burpsuite`, and other installed scanners/fuzzers.

**Payload coverage:** Designed to explore unlimited payload variants for SQL injection, CSV injection, open redirect, XSS, SSRF, command injection, template injection, path traversal, deserialization, prototype pollution, auth bypass, business logic abuse, IDOR, CSRF, response splitting, and more.

**Reference setup files:** `references/setup.md` and `references/local-tooling.md` contain the actual Deepseek CLI, local tooling, and vulnerability environment instructions the skill uses.

**Report formats:** HackerOne · Bugcrowd · Intigriti · Immunefi · Generic

---

## AI Pentesting Tool — bountyforge.xyz

Take BountyForge hunting without spinning up your own environment. **[bountyforge.xyz](https://bountyforge.xyz)** hosts the same engine in isolated pentesting sandboxes:

- Firecracker microVM per session — your AI key, your box, your report
- Full `recon → hunt → triage → H1-ready report` pipeline in the browser
- No rate limits, no AI slop — clean, isolated execution
- Hosted skill releases managed from this repo

> **Choose your platform:** install the open-source skill here, or hunt in the cloud at [bountyforge.xyz](https://bountyforge.xyz).

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

### Optional: Bug Bounty Intelligence MCP (smart contract scanning)

For automated Solidity scanning with Al-Mizaan v3 7-gate analysis, add the companion MCP server:

```bash
claude mcp add bug-bounty-intelligence -- npx -y bug-bounty-intelligence-mcp@latest
```

Or in `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "bug-bounty-intelligence": {
      "command": "npx",
      "args": ["-y", "bug-bounty-intelligence-mcp@latest"]
    }
  }
}
```

**Tools available:**
| Tool | Cost | Purpose |
|------|------|---------|
| `scan_contract` | $5 USDC on Base | Submit a public Solidity repo for AI security analysis |
| `get_scan_report` | Free | Poll scan status and get report URL |
| `list_vulnerability_patterns` | Free | Acceptance rates from 1,032 reconciled Sherlock findings |

BountyForge auto-detects the MCP and uses `list_vulnerability_patterns` (free) for pre-hunt bug-class prioritization. See `references/bug-bounty-intelligence-mcp.md` for full integration guide.

---

## Enabling Claude Code Execution (local execution)

To allow BountyForge to run local tools and subagents, enable Claude Code (local execution) in your Claude environment and grant the skill permission to execute shell commands.

macOS / Linux (Claude Code client):

1. Start Claude Code with code-execution enabled (follow your Claude Code client docs).
2. Ensure the shell that launches Claude Code has the tools you want on `PATH` (e.g., `nmap`, `ffuf`, `sqlmap`).
3. If using project-specific env vars, source your project file before starting Claude Code:

```bash
source .env            # or project.env
claude start           # or the command your Claude Code client uses
```

Windows (Claude.app / PowerShell):

1. Open PowerShell as the user that runs Claude.
2. Set any project env vars or tokens (example shown in `references/setup.md`).
3. Launch Claude with code execution enabled from the same session so it inherits the environment.

Notes:
- If you are using the web/app variant, go to **Settings → Capabilities** and toggle **Code execution** on. Some deployments require you to enable a "subagent" or "local tooling" checkbox; consult your Claude distribution docs.
- Always start Claude from the shell that has your project environment loaded so `deepseek export`, `nmap`, and other tools are available to the skill.
- For privacy and safety, grant execution permission only for trusted skills and projects.


## Deepseek Pro Setup (Claude CLI)

BountyForge includes `references/setup.md` so the skill can use the same Deepseek CLI environment and local tooling configuration during audit runs.

### Mac / Linux

In your project shell or project file, export:

```bash
export ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
export ANTHROPIC_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash
export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash
export CLAUDE_CODE_EFFORT_LEVEL=max
export ANTHROPIC_AUTH_TOKEN="your-deepseek-pro-token"
```

Then bind the current repo:

```bash
deepseek export --project . --key "$ANTHROPIC_AUTH_TOKEN" --mode pro
```

Start Claude CLI from the same shell so the environment variables are active.

### Windows (PowerShell)

Use these variables in the current session:

```powershell
$env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
$env:ANTHROPIC_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_EFFORT_LEVEL = "max"
$env:ANTHROPIC_AUTH_TOKEN = "your-deepseek-pro-token"

deepseek export --project . --key $env:ANTHROPIC_AUTH_TOKEN --mode pro
```

For persistence, add the same variables to your PowerShell profile.

> Note: this setup is intended for temporary use inside a project or shell session so the Deepseek CLI export command can be applied without modifying the core skill files.

---

## Usage

### How to use Bounty Forge

1. **Choose a precise scope.** For bug bounty work, point the skill at the exact contract file, API endpoint list, or web target you are testing.
2. **Enable code execution.** When Claude Code can run locally, Bounty Forge can orchestrate local tools like `nmap`, `ffuf`, `amass`, `sqlmap`, `gobuster`, `curl`, `httpx`, and `zap`.
3. **Run an audit command.** Use the examples below and include `--file-output` or `--cvss` when you want a formatted deliverable.
4. **Review findings.** The skill will classify and gate each finding, but always validate exploitability before submitting.
5. **Generate a report.** Use the built-in report mode to turn confirmed findings into platform-ready output.

### Audit a contract or repo

```
audit contracts/
```
```
run bountyforge on src/usdc.move --platform immunefi --cvss --file-output
```
>/bountyforge <targetfile>
```
check this contract for vulns --platform h1 --cvss
```

### Web / API target

```
/bountyforge on https://api.target.com
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
├── CHANGELOG.md                      # Release notes
└── references/
    ├── judging.md                    # 4-gate evaluation rules
    ├── supervisor.md                 # Detailed triage supervisor system
    ├── knowledge.md                  # Disclosed-report knowledge base
    ├── report-formatting.md          # Platform report templates
    ├── cvss-guide.md                 # CVSS 3.1 scoring guide
    ├── setup.md                      # Deepseek CLI environment guidance
    ├── local-tooling.md              # Local tooling and vuln coverage reference
    ├── al-mizaan-gates.md            # Al-Mizaan v3 7-gate deep validation (from Bug Bounty Intelligence MCP)
    ├── sis-intelligence.md           # SIS-MD passive security intelligence integration
    ├── isolation.md                  # Agent isolation rules and boundary enforcement
    ├── attack-vectors/
    │   ├── web-api-vectors.md
    │   ├── smart-contract-vectors.md
    │   ├── business-logic-vectors.md
    │   └── ...
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

---

## Collaboration & Integrated Projects

BountyForge v3.1.0 integrates methodologies from:

| Project | What We Integrated | Reference |
|---------|-------------------|-----------|
| [Bug Bounty Intelligence MCP](https://github.com/holistis/bug-bounty-intelligence-mcp) | Al-Mizaan v3 7-gate deep validation framework, scope-aware filtering methodology, vulnerability acceptance rates from 27,681 Sherlock/Code4rena findings | `references/al-mizaan-gates.md` |
| [3ilm MCP](https://github.com/holistis/3ilm-mcp) | Free vulnerability pattern lookup (sibling project) | Resources section |
| [SIS-MD Security Intelligence SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-) | Passive security intelligence modules (metadata, secrets, fingerprinting), boundary enforcement rules, structured report format | `references/sis-intelligence.md` |

**Key lessons integrated:**
- **From Bug Bounty Intelligence:** 100% of Slither's "High" findings on a mature protocol were false positives — 89% were out-of-scope `lib/` noise. Scope-aware, context-aware analysis eliminates this class of error entirely.
- **From SIS-MD:** Passive analysis before active hunting catches metadata leaks, secret sprawl, and technology misconfigurations that active scanners miss. Masked reporting prevents the report itself from becoming a leak vector.

---

## Disclaimer

BountyForge is intended for authorized security research and bug bounty programs only. Only use it against targets you have explicit permission to test. The author is not responsible for misuse.

---

Built by [@Gabson0x](https://github.com/Gabson0x) · [Synq Studio](https://github.com/synqstudio)