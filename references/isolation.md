# Agent Isolation Rules — BountyForge

Ensures every specialized agent operates within its defined boundaries. Prevents cross-contamination, scope creep, and false findings from agents operating outside their domain.

## Core Principle

Each agent has a defined **Owns / Queries / Never Touches** contract (defined in `shared-rules.md`). Isolation enforcement means:

1. An agent MUST NOT report findings outside its owned domain
2. An agent MUST NOT execute operations it doesn't own
3. An agent MUST hand off discoveries outside its domain via the AgentBus signal system
4. An agent MUST respect scope boundaries (no testing out-of-scope assets)

## Isolation Dimensions

### 1. Domain Isolation
Each agent owns specific bug classes and attack surfaces. Cross-domain findings without a proper handoff signal are rejected.

| Agent | Owns | Must Not Report |
|-------|-------|-----------------|
| web-api-agent | Injection, XSS, SSRF, auth bypass, smuggling | Smart contract bugs, economic attacks |
| smart-contract-agent | Reentrancy, overflow, access control, storage | Web injection, XSS, CSRF |
| access-control-agent | IDOR, privilege escalation, role bypass | Race conditions, oracle manipulation |
| business-logic-agent | State machine, payment logic, workflow abuse | Cryptographic flaws, memory corruption |
| race-condition-agent | TOCTOU, front-running, concurrency | Business logic, access control |
| economic-security-agent | Flash loans, oracle manipulation, tokenomics | Web injection, XSS |
| recon-agent | Subdomains, exposed services, cloud misconfig | Any active exploitation |
| credential-leak-agent | GitHub tokens, .env, build log secrets | Active exploitation of found credentials |

### 2. Scope Isolation
Agents must verify every target against the program's scope before testing:

- Check domain/IP against scope page
- Verify asset ownership (is this really the target's infrastructure?)
- Respect scope exclusions (no testing `lib/`, `test/`, `mocks/`, third-party dependencies)
- Honor rate limits and testing windows

**Kill if:** Agent tests an out-of-scope asset without explicit scope expansion approval.

### 3. Execution Isolation
Agents have defined execution permissions:

| Permission Level | Allowed Actions | Agents |
|-----------------|-----------------|--------|
| **Passive-only** | Read, observe, fingerprint | recon-agent, credential-leak-agent |
| **Read-only probing** | GET requests, public data access | web-api-agent, access-control-agent, graphql-agent |
| **Active testing** | Payload injection, auth bypass attempts | All hunt agents (with authorization) |
| **Destructive testing** | Write/delete operations, state changes | Only with explicit user approval |

### 4. Data Isolation
Agent findings must not cross-contaminate:

- Each agent's findings stay in its own namespace until deduplication
- Finding IDs are prefixed with agent name for traceability
- Cross-agent chains are built by KillChainBuilder, not by agents directly
- Shared state goes through AgentBus signals, not direct file writes

### 5. Model/Context Isolation
Prevents prompt injection and context leakage between agents:

- Agent bundles are self-contained (no shared mutable state in prompts)
- Agent output is sanitized before being fed to other agents
- Rogue/counter-intelligence agents operate in separate context windows
- Adversarial refutation runs with a different model configuration

## Isolation Check Protocol

Before an agent's findings are accepted, run through these checks:

### Check 1: Domain Authorization
```
[ ] Finding bug class is in agent's owned domain
[ ] If cross-domain, a proper handoff signal was emitted via AgentBus
[ ] Agent did not "drift" into another agent's specialty
```

### Check 2: Scope Compliance
```
[ ] Every tested endpoint/asset is in the program's scope
[ ] No testing of excluded paths (lib/, test/, third-party)
[ ] No testing of assets not owned by the target organization
[ ] Rate limits and testing windows were respected
```

### Check 3: Execution Boundary
```
[ ] Agent stayed within its permission level
[ ] No destructive testing without explicit authorization
[ ] Passive-only agents did not send active probes
[ ] No exploitation of found vulnerabilities (demonstrate only, don't exfiltrate)
```

### Check 4: Data Integrity
```
[ ] Finding has agent-specific prefix in ID
[ ] Evidence is from the agent's own testing, not copied from another agent
[ ] Cross-agent references use AgentBus signal IDs, not raw findings
[ ] No hallucinated endpoints or responses
```

### Check 5: Context Safety
```
[ ] Agent bundle contained only its own reference files
[ ] No prompt injection vectors in agent input
[ ] Agent output was sanitized before cross-agent sharing
[ ] Refutation ran with independent model configuration
```

## Violation Responses

| Violation | Response |
|-----------|----------|
| Domain drift | Quarantine finding, signal correct agent via AgentBus |
| Scope violation | Kill finding immediately, log scope boundary issue |
| Execution overstep | Downgrade finding to LEAD, flag for manual review |
| Data cross-contamination | Quarantine both agents' findings, re-run independently |
| Context safety | Kill all affected findings, restart agents with clean bundles |

## Integration with SIS-MD Boundaries

The SIS-MD passive analysis rules (`references/sis-intelligence.md`) add an additional layer:

1. **Passive analysis only** — recon and fingerprinting agents must not send active probes
2. **Redact, don't repeat** — no live secrets in any agent output
3. **Authorization is the user's responsibility** — agents must verify before testing
4. **No speculative CVEs** — version-based findings must not fabricate CVE IDs
5. **Severity is evidence-based** — no inflation, no alarmism

## Integration with Al-Mizaan Gates

The Al-Mizaan framework (`references/al-mizaan-gates.md`) reinforces isolation through:

- **Gate 3 (Threat Model):** Only consider triggers within the agent's authorized scope
- **Gate 1 (Code Reading):** Read only in-scope code — skip `lib/`, `interfaces/`, `mocks/`
- **Gate 4 (Invariant Breach):** Verify the invariant is actually a security boundary, not a design choice

The Slither benchmark lesson applies: 89% of Slither's "High" findings were out-of-scope `lib/` noise. Scope-aware isolation prevents this class of false positive entirely.
