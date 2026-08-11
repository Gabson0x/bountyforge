# Bug Bounty Intelligence MCP — Integration Guide

MCP server for AI-powered smart contract security analysis. Trained on 27,681 Sherlock/Code4rena findings. [GitHub](https://github.com/holistis/bug-bounty-intelligence-mcp) | npm: `bug-bounty-intelligence-mcp@latest`

## Available Tools

### `scan_contract` — Paid ($5 USDC on Base via x402)

Submits a public GitHub repo for AI-powered security analysis using the Al-Mizaan v3 7-gate framework.

```
Parameters:
  repo_url (required): Public GitHub repo URL (Solidity)
  protocol_type (optional): DEX | LENDING | BRIDGE | GOVERNANCE | STAKING | GENERAL

Returns: job_id for polling status
Cost: $5 USDC on Base (eip155:8453)
Delivery: Within 24 hours
```

### `get_scan_report` — Free

Polls the status of a submitted scan and returns the report URL when complete.

```
Parameters:
  job_id (required): The job ID from scan_contract

Returns: queued | processing | complete + report_url
```

### `list_vulnerability_patterns` — Free

Returns acceptance-rate percentages from exactly-reconciled Sherlock contests. No payment, no API key required.

```
Parameters:
  protocol_type (optional): DEX | LENDING | BRIDGE | GOVERNANCE | STAKING | GENERAL

Returns: Per-pattern acceptance rates with example findings
```

## Setup — Claude Code MCP Configuration

Add to `~/.claude/settings.json` or Claude Desktop config:

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

Or via Claude Code CLI:

```bash
claude mcp add bug-bounty-intelligence -- npx -y bug-bounty-intelligence-mcp@latest
```

After setup, the tools `scan_contract`, `get_scan_report`, and `list_vulnerability_patterns` become available to BountyForge.

## When to Use Each Tool

| Scenario | Tool | Cost |
|----------|------|------|
| Pre-hunt prioritization — which bug classes pay? | `list_vulnerability_patterns` | Free |
| Auditing an unfamiliar protocol — what patterns matter? | `list_vulnerability_patterns` | Free |
| Full automated scan of a public Solidity repo | `scan_contract` | $5 USDC |
| Checking scan results | `get_scan_report` | Free |
| Cross-referencing BountyForge findings against acceptance data | `list_vulnerability_patterns` | Free |

## Usage in BountyForge Orchestration

### Pre-Hunt (with --learn or --solidity)

Before spawning agents, check acceptance rates for the protocol type:

```
Call list_vulnerability_patterns(protocol_type="LENDING")
→ Returns: oracle-manipulation 36% (131 cases), staleness 49% (174 cases), ...
→ Prioritize agents for high-acceptance, high-n patterns
→ Skip or deprioritize low-acceptance patterns (liquidation 29%, n=14)
```

### During Smart Contract Audit

Optionally submit for automated scanning:

```
Call scan_contract(repo_url="https://github.com/org/repo", protocol_type="LENDING")
→ Returns job_id
→ Poll get_scan_report(job_id) until complete
→ Cross-reference BountyForge findings with scan results
```

### Post-Hunt Validation

Use acceptance rates to calibrate confidence scores:

| Acceptance Rate | Confidence Adjustment |
|----------------|----------------------|
| > 60% | +10 confidence (well-established pattern) |
| 40-60% | No adjustment (moderate signal) |
| < 40% | -10 confidence (low historical acceptance, require stronger PoC) |
| n < 20 | Flag as low-sample (directional only, don't adjust) |

## Vulnerability Acceptance Rates (CC0 — Embedded)

Data from 1,032 exactly-reconciled findings across 10 Sherlock contests. Source: `vulnerability-acceptance-rates.json` (CC0 licensed).

| Pattern | Acceptance | Accepted/Total | Signal Strength |
|---------|-----------|----------------|-----------------|
| reentrancy | 78% | 40/51 | High (n=51) |
| overflow | 58% | 26/45 | Moderate (n=45) |
| trusted-actor | 51% | 159/311 | High (n=311) |
| fee-miscalculation | 50% | 55/109 | High (n=109) |
| staleness | 49% | 86/174 | High (n=174) |
| mev-slippage | 49% | 44/89 | Moderate (n=89) |
| access-control | 47% | 35/74 | Moderate (n=74) |
| flash-loan | 46% | 6/13 | Low (n=13) |
| dos-griefing | 41% | 64/156 | High (n=156) |
| rounding | 40% | 25/63 | Moderate (n=63) |
| oracle-manipulation | 36% | 47/131 | High (n=131) |
| liquidation | 29% | 4/14 | Low (n=14) |

### Protocol-Specific Pattern Mapping

| Protocol Type | Relevant Patterns (in priority order) |
|---------------|--------------------------------------|
| DEX | oracle-manipulation, mev-slippage, rounding, flash-loan, fee-miscalculation, reentrancy |
| LENDING | oracle-manipulation, staleness, liquidation, rounding, access-control, reentrancy |
| BRIDGE | access-control, reentrancy, overflow, trusted-actor, dos-griefing |
| GOVERNANCE | trusted-actor, access-control, dos-griefing, overflow |
| STAKING | rounding, trusted-actor, access-control, dos-griefing |
| GENERAL | access-control, reentrancy, overflow, trusted-actor, dos-griefing |

## Limitations (from METHODOLOGY.md)

- Only 10 of 105 crawled Sherlock contests reconciled exactly (1,032 of 27,681 findings)
- Tagging uses substring matching at ~65% precision — directional, not exact
- Low-n rows (liquidation n=14, flash-loan n=13) are lower confidence
- Data measures submission reliability, not real-world exploit frequency
- Does not cover silent misses (bugs never submitted)

## Sibling Project

[3ilm MCP](https://github.com/holistis/3ilm-mcp) — free-only MCP server with `search_vulnerabilities`, `get_pattern_details`, `list_patterns`. No paid tier. For users who only want pattern lookup.
