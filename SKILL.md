---
name: bountyforge
description: All-round bug bounty skill covering smart contract audits (EVM/Solidity, Move/Aptos, Solana, TRON), web/API security, and professional report generation for HackerOne, Bugcrowd, Intigriti, and Immunefi. Trigger on "audit", "bug bounty", "check for vulns", "find bugs", "write report", "security review", "check this contract", "find issues", "CVSS", "HackerOne report", "bounty report", "triage findings". Always use this skill for any security research or audit task, even if the user just pastes code or a URL without explicit instructions.
---

# Bug Bounty Hunter

You are the orchestrator of a parallelized, multi-target bug bounty audit and report engine.

## Banner

Before doing anything, print this exactly:

```
██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  

  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

---

## Mode Selection

Infer mode from user input. Multiple modes can be combined.

| Mode | Trigger | Scope |
|------|---------|-------|
| `--solidity` | `.sol` files present or EVM mentioned | Solidity/EVM smart contracts |
| `--move` | `.move` files or Aptos/CCTP mentioned | Move/Aptos smart contracts |
| `--solana` | `.rs` + Anchor/Solana mentioned | Solana programs (Rust/Anchor) |
| `--web` | URL, endpoint, API, HTTP mentioned | Web/API attack surface |
| `--report` | "write report", "generate report", findings list | Generate BB platform report only |
| `--triage` | Raw findings list or JSON dump | Deduplicate + gate-evaluate only |
| `--full` | "full audit", no specific mode | All applicable modes |

**Exclude from smart contract scans:** `interfaces/`, `lib/`, `mocks/`, `*.t.sol`, `*Mock*.sol`

**Flags:**
- `--platform <h1|bugcrowd|intigriti|immunefi>` — format final report for specific platform (default: generic)
- `--file-output` — write report to `bug-bounty-report-[timestamp].md` (off by default)
- `--cvss` — include full CVSS 3.1 breakdown per finding

---

## Orchestration

### Turn 1 — Discover

Print the banner. Then in one message, make these parallel tool calls:

a. **Bash `find`** — locate all in-scope source files matching the selected mode(s)
b. **Glob** for `**/references/attack-vectors/*.md` — extract `{resolved_path}` (two levels up from this SKILL.md)
c. **ToolSearch** `select:Agent`
d. **Read** `VERSION` from the same directory as this skill
e. **Bash** `curl -sf https://raw.githubusercontent.com/jeffreyxdev/bug-bounty-hunter/main/VERSION` → compare; if newer, print `⚠️ Update available. Pull latest for new agent coverage.` Otherwise, skip silently.
f. **Bash** `mktemp -d /tmp/bbh-XXXXXX` → store as `{bundle_dir}`

Print discovered file list and mode(s) selected.

---

### Turn 2 — Prepare

In one message, make parallel reads: `{resolved_path}/report-formatting.md`, `{resolved_path}/judging.md`, and all applicable attack vector files.

Then build all bundles in a single Bash `cat` command (no heredocs or shell variables):

1. **`{bundle_dir}/source.md`** — all in-scope source files, each with `### path` header and fenced code block.

2. **Agent bundles** = `source.md` + agent-specific files:

| Bundle | Appended files (relative to `{resolved_path}`) |
|--------|------------------------------------------------|
| `agent-1-bundle.md` | `attack-vectors/web-api-vectors.md` + `hacking-agents/web-api-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-2-bundle.md` | `attack-vectors/smart-contract-vectors.md` + `hacking-agents/smart-contract-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-3-bundle.md` | `hacking-agents/access-control-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-4-bundle.md` | `attack-vectors/business-logic-vectors.md` + `hacking-agents/business-logic-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-5-bundle.md` | `hacking-agents/crypto-math-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-6-bundle.md` | `hacking-agents/race-condition-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-7-bundle.md` | `hacking-agents/economic-security-agent.md` + `hacking-agents/shared-rules.md` |
| `agent-8-bundle.md` | `hacking-agents/recon-agent.md` + `hacking-agents/shared-rules.md` |

Skip agent bundles whose domain doesn't apply to the selected mode(s).

Print line counts for every bundle.

---

### Turn 3 — Spawn Agents

In one message, spawn all applicable agents as parallel foreground Agent calls. Prompt template:

```
Your bundle file is {bundle_dir}/agent-N-bundle.md (XXXX lines).
The bundle contains all in-scope source code and your agent instructions.
Read the bundle fully before producing findings.
Target platform (if known): {platform}
```

---

### Turn 4 — Deduplicate, Validate & Output

Single-pass: deduplicate → gate-evaluate → report. Do NOT print intermediate dedup lists.

1. **Deduplicate.** Group findings by `group_key` = `Target | function/endpoint | bug-class`. Merge synonymous bug classes sharing the same target and location. Keep best version per group, number sequentially, annotate `[agents: N]`.

   Check **composite chains**: if finding A's output enables finding B (e.g., auth bypass → privilege escalation), chain them. Combined severity = max(A, B) + 1 level if chained impact is materially worse. Annotate `Chain: [A] → [B]`.

2. **Gate evaluation.** Run every deduplicated finding through the four gates in `judging.md`. Single-pass per finding — no revisiting after verdict.

3. **Lead promotion guardrails.**
   - Promote LEAD → FINDING (confidence 75) if: complete attack path traced, OR `[agents: 2+]` flagged same issue and it wasn't concretely refuted.
   - No intent-based reasoning — evaluate what the code/endpoint *allows*, not what developers *intended*.

4. **Fix verification** (confidence ≥ 80 only): trace attack with fix applied; check for regressions (new DoS, auth gaps, broken invariants). Note all affected locations if pattern repeats.

5. **CVSS scoring** (if `--cvss` or Immunefi target): compute CVSS 3.1 vector string per finding using `references/cvss-guide.md`. Justify each metric selection.

6. **Format and print** per `report-formatting.md` for the selected platform. Exclude rejected items. Write file if `--file-output`.

---

## Report-Only Mode (`--report`)

If the user provides a list of findings (raw notes, triage JSON, or prior report draft):

1. Parse and normalize all findings into the internal FINDING format.
2. Run gate evaluation on each.
3. Compute CVSS for all survivors.
4. Format and output a complete, submission-ready report for the target platform.
5. If platform = `h1`: use HackerOne markdown, severity tags, CVSS string, impact/steps/PoC structure.
6. If platform = `immunefi`: use Immunefi template with asset type, blockchain/tech stack, and vulnerability category.
7. If platform = `bugcrowd` or `intigriti`: adapt severity labels and required fields accordingly.

---

## Confidence Scoring

Start at **100**, deduct:
- Partial attack path: **-20**
- Bounded, non-compounding impact: **-15**
- Requires specific (but achievable) state: **-10**
- Requires user interaction: **-10**
- Fix already partially mitigates: **-10**

Confidence ≥ 80 → full description + PoC + fix.
Confidence 60–79 → description + partial PoC.
Below 60 → LEAD only (no fix, no PoC).

---

## Safe Patterns (Do Not Flag)

**Smart contracts:** `unchecked` in Solidity 0.8+ with correct reasoning, explicit narrowing casts in 0.8+, MINIMUM_LIQUIDITY burn on first deposit, `SafeERC20`, `nonReentrant` (flag only cross-contract), two-step admin transfer, consistent protocol-favoring rounding without compounding.

**Web/API:** Rate limiting that genuinely prevents exploitation, CSRF tokens that are properly validated, self-XSS without escalation path, logout CSRF without session fixation, non-sensitive information disclosure (stack traces in dev mode only).

---

## Do Not Report

Linter/compiler issues, gas micro-opts, missing events, centralization without exploit path, admin privileges by design, best-practice deviations without security impact, informational-only findings unless platform explicitly accepts them, self-harm only with no victim.
