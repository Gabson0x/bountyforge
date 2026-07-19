# Shared Agent Rules

These rules apply to ALL bug bounty hunter agents regardless of specialization.

## Output Format

Every finding must use this exact structure:

```
FINDING
  id: <sequential number>
  title: <≤10 words, impact-first>
  target: <contract name / endpoint / file path>
  location: <function name / line number / URL path>
  bug_class: <canonical class — see list below>
  group_key: <Target | location | bug_class>
  severity: critical | high | medium | low | informational
  confidence: <0–100>
  attack_path: <numbered steps — be concrete, quote exact code/params>
  impact: <who loses what, quantify if possible>
  poc: |
    <minimal working PoC — code, curl command, or step sequence>
  fix: <specific remediation — line-level where possible>
  agents: [<your agent name>]
```

For leads (incomplete paths):

```
LEAD
  id: <sequential>
  title: <≤10 words>
  target: <target>
  location: <location>
  bug_class: <class>
  group_key: <Target | location | bug_class>
  smell: <what looks wrong>
  unverified: <what you couldn't confirm>
  agents: [<your agent name>]
```

## Canonical Bug Classes

**Smart Contract:** reentrancy, integer-overflow, integer-underflow, precision-loss, access-control-bypass, unprotected-initializer, storage-collision, front-running, oracle-manipulation, flash-loan-attack, signature-replay, cross-chain-replay, missing-zero-address-check, unchecked-return-value, denial-of-service, griefing, upgrade-bypass, delegatecall-injection, price-manipulation, invariant-violation, race-condition-sc, orphaned-role, emergency-misuse

**Web/API:** idor, broken-auth, jwt-bypass, ssrf, sqli, csv-injection, xss-stored, xss-reflected, xss-dom, xxe, rce, path-traversal, open-redirect, csrf, graphql-introspection, business-logic, race-condition-web, mass-assignment, insecure-deserialization, info-disclosure, cors-misconfiguration, account-takeover, privilege-escalation-web, api-key-exposure, oauth-bypass, subdomain-takeover, cache-poisoning, request-smuggling, parameter-pollution, http-response-splitting, host-header-injection

## Severity Calibration

| Severity | Smart Contract | Web/API |
|----------|---------------|---------|
| Critical | Direct fund drain, >$1M at risk, protocol shutdown | RCE, full account takeover, mass data breach |
| High | Fund drain with preconditions, governance takeover, major invariant break | Auth bypass, IDOR on sensitive data, persistent XSS on admin |
| Medium | Partial fund loss, temporary DoS, privilege escalation | IDOR on non-sensitive data, SSRF to internal, self-XSS with escalation |
| Low | Griefing, dust loss, minor invariant, excess gas cost | Info disclosure, non-exploitable misconfig, low-impact logic flaw |
| Info | Best-practice deviation, no direct exploit | No security impact, hardening recommendation |

## Behavior Rules

1. **Never assume intent.** Evaluate what the code/endpoint *allows*, not what it was *meant* to do.
2. **Quote exact code.** Every finding references the exact line, function name, or HTTP parameter responsible.
3. **Trace complete paths.** If you cannot trace from entry to impact, output a LEAD, not a FINDING.
4. **No duplicate speculation.** If another agent's domain clearly owns a finding class, do not re-report it. Flag it as cross-domain if it connects to your area.
5. **Composite chains.** If your finding's output enables a higher-severity impact by combining with another class, note `chain_with: <bug_class>`.
6. **Platform awareness.** If a target platform is specified, calibrate severity to that program's known policies (e.g., Immunefi critical = >$1M protocol funds; HackerOne/Bugcrowd varies by program).
7. **No invented facts.** If a variable, endpoint, or behavior isn't visible in the source, say "not visible in scope" rather than assuming.

---

## Agent Cross-Communication Protocol v2.1

Agents signal findings to each other using structured broadcast messages. This enables autonomous chain building and prevents duplicate work.

### Broadcast Format

Every agent can emit these signal types:

```
BROADCAST <signal_type>
  from_agent: <agent name>
  to_agents: [<target agents> | * for all]
  priority: critical | high | medium | low
  finding_ref: <finding_id or lead_id>
  signal_data:
    <type-specific fields>
```

### Signal Types

#### 1. DISCOVERY — "I found something in your domain"

Used when Agent A finds a pattern that Agent B should investigate deeper.

```
BROADCAST discovery
  from_agent: web-api-agent
  to_agents: [access-control-agent]
  priority: high
  finding_ref: F-0012
  signal_data:
    pattern: idor_read
    endpoint: GET /api/v2/orders/{id}
    note: "No ownership check on order detail — check if PUT/DELETE also unguarded"
    evidence_hash: <blake3 of captured response>
```

#### 2. HANDOFF — "This is yours, I'm done here"

Used when an agent confirms a finding belongs to another domain.

```
BROADCAST handoff
  from_agent: web-api-agent
  to_agents: [business-logic-agent]
  priority: high
  finding_ref: F-0015
  signal_data:
    reason: "Not injection — the parameter is used in business rule evaluation"
    context: "Coupon code parameter evaluated server-side with stackable logic"
    test_results:
      - "COUPON10 + COUPON20 = 30% discount (should be max 20%)"
```

#### 3. CHAIN — "Your bug + my bug = critical"

Used when combining findings across agents creates higher severity.

```
BROADCAST chain
  from_agent: web-api-agent
  to_agents: [access-control-agent]
  priority: critical
  finding_ref: F-0003
  signal_data:
    bug_a: "F-0003: Open redirect on /auth/callback"
    bug_b: "F-0007: OAuth state parameter not validated"
    combined_impact: "Full account takeover via OAuth code theft"
    combined_severity: critical
    chain_type: open_redirect_to_oauth_ato
    preconditions: "Victim clicks crafted link while logged out"
    reliability: 0.85
```

#### 4. ALERT — "Avoid this area"

Used when an agent detects a honeypot, WAF trap, or dead end.

```
BROADCAST alert
  from_agent: counter-intelligence-agent
  to_agents: [*]
  priority: critical
  finding_ref: null
  signal_data:
    alert_type: honeypot | waf_trap | dead_end | rate_limit | active_defender
    endpoint: /admin/debug
    reason: "Hidden form field + generic 200 response + fake credentials"
    action: "ALL AGENTS: Do not probe this endpoint"
```

#### 5. REQUEST — "I need data from your domain"

Used when an agent needs analysis from another specialist.

```
BROADCAST request
  from_agent: business-logic-agent
  to_agents: [race-condition-agent]
  priority: medium
  finding_ref: L-0008
  signal_data:
    request_type: race_analysis
    endpoint: POST /api/checkout
    context: "Two concurrent coupon applications may stack"
    parameters: ["coupon_code", "cart_total"]
    desired_answer: "Is there a TOCTOU window between coupon validation and application?"
```

#### 6. PROMOTION — "Lead → Finding confirmed"

Used when a LEAD is promoted to a full FINDING by cross-agent collaboration.

```
BROADCAST promotion
  from_agent: access-control-agent
  to_agents: [web-api-agent, supervisor]
  priority: high
  finding_ref: F-0023
  signal_data:
    lead_ref: L-0004
    promoted_by: "Cross-referenced with recon-agent's endpoint map"
    new_severity: high
```

### Cross-Agent Chain Registry

| Chain Pattern | Agent A | Agent B | Combined Severity | Real Example |
|---------------|---------|---------|-------------------|--------------|
| Open redirect → OAuth ATO | web-api-agent | access-control-agent | Critical | PayPal, Shopify |
| IDOR read → IDOR write | web-api-agent | access-control-agent | High→Critical | H1 #792927 |
| SSRF → cloud metadata → RCE | web-api-agent | recon-agent | Critical | Shopify $11K |
| XSS → session hijack | web-api-agent | access-control-agent | High→Critical | Slack |
| Cache poison → stored XSS | web-api-agent | recon-agent | Critical | PayPal $20K |
| Email bypass → SSO takeover | business-logic-agent | access-control-agent | Critical | Shopify |
| Race condition → double spend | race-condition-agent | economic-security-agent | Critical | Multiple DeFi |
| GraphQL introspect → mass PII exfil | web-api-agent | recon-agent | High→Critical | H1 #489146 |
| HTTP smuggling → session theft | web-api-agent | access-control-agent | Critical | Slack, Zomato |
| Subdomain takeover → auth bypass | recon-agent | access-control-agent | High | Multiple |
| CI/CD exposure → supply chain | recon-agent | web-api-agent | Critical | PayPal $30K |
| Business logic → privilege escalation | business-logic-agent | access-control-agent | High | Shopify |

### Agent Directory

Each agent registers its domain boundaries:

| Agent | Owns | Queries | Never Touches |
|-------|------|--------|---------------|
| web-api-agent | HTTP vulns (XSS, SQLi, SSRF, CSRF, smuggling) | Auth state, business rules | Smart contracts, crypto math |
| access-control-agent | Roles, permissions, auth bypass, IDOR | Token formats, session state | Injection, business logic |
| business-logic-agent | State machines, workflow bypass, limits | Auth checks, race windows | Code injection, crypto |
| race-condition-agent | TOCTOU, front-running, concurrency | Business rules, auth state | Static vulnerabilities |
| smart-contract-agent | Solidity/Move/Solana vulns | Economic models, math | Web/API attacks |
| economic-security-agent | Oracle manipulation, flash loans, tokenomics | Contract state, math | Web attacks |
| crypto-math-agent | Integer bugs, crypto primitives, EIP-712 | Contract logic, economics | Web attacks |
| recon-agent | Subdomains, cloud assets, secrets, fingerprinting | All agents (provides surface map) | Code-level vulns |
| counter-intelligence-agent | Honeypots, WAF, canaries, active defense | All agents (provides threat intel) | Finding bugs |
| regression-agent | Fix verification, bypass discovery, patch gaps | All agents (re-tests findings) | Initial discovery |

### Cross-Agent Workflow Example

```
1. recon-agent: DISCOVERY → web-api-agent
   "Found GraphQL endpoint at /graphql with introspection enabled"

2. web-api-agent: DISCOVERY → access-control-agent
   "GraphQL schema shows User type with email, ssn fields — check field-level auth"

3. access-control-agent: CHAIN → web-api-agent
   "Query {users{nodes{email}}} returns data with low-privilege token"
   "Combined: GraphQL introspection + missing field auth = mass PII exfil"
   "Severity: critical"

4. web-api-agent: PROMOTION → supervisor
   "Lead L-0003 promoted to Finding F-0018: Mass PII exfil via GraphQL"
   "Severity: critical, CVSS 9.8"

5. counter-intelligence-agent: ALERT → [*]
   "WAF detected on graphql endpoint after 50 queries — rate limit in effect"
   "All agents: switch to low-signal mode, rotate IPs"
```

### Implementation Notes

When implementing agent cross-communication in code:

```python
# tools/agent_bus.py — Agent communication bus
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json

@dataclass
class Signal:
    signal_type: str  # discovery, handoff, chain, alert, request, promotion
    from_agent: str
    to_agents: List[str]
    priority: str
    finding_ref: Optional[str]
    signal_data: Dict[str, Any]
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_finding_context(self) -> str:
        """Render as context for the receiving agent."""
        return f"""
CROSS-AGENT SIGNAL [{self.priority.upper()}]
From: {self.from_agent}
Type: {self.signal_type}
Finding: {self.finding_ref}
Data: {json.dumps(self.signal_data, indent=2)}
"""
```

The signal bus is implemented in `tools/agent_bus.py` and persisted to `state/signals/{target}/`. Each agent reads incoming signals before starting its hunt and writes outgoing signals as it discovers cross-domain patterns.
