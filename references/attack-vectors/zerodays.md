# Zero-Day Hunting — The BountyForge v3 Mindset

## Why Normal Agents Miss What Top Researchers Find

A normal security agent scans for **vulnerabilities** — it has a list of bug classes (XSS, SQLi, IDOR) and pattern-matches against them. It sees `?redirect_url=` and thinks "open redirect." It sees `SELECT * FROM` and thinks "SQLi." This is checklist auditing, and it finds checklist bugs.

Top researchers don't hunt vulnerabilities. They hunt **capabilities**.

A capability is a primitive: "I can control the value of this parameter," "I can reach this sink," "I can forge this header," "I can make this server fetch a URL I choose." Capabilities are building blocks. They are **what the attacker can actually do**, not what the bug class is called.

The gap between checklist auditing and actual zero-day hunting is that **individual capabilities are usually not bugs**. A reflected parameter is not a vulnerability. A server that makes outbound HTTP requests is not a vulnerability. But when you map how capabilities chain across trust boundaries — the parameter that becomes a header that reaches an internal service that trusts all headers — you find what no checklist catches.

## The Architecture That Should Feel Illegal

BountyForge v3 runs like this:

```
                  ┌──────────────────────────────┐
                  │     TRUST MAP OF TARGET       │
                  │  ┌─────┐    ┌─────┐          │
                  │  │ CDN  │◄───│ App │──► DB   │
                  │  └─────┘    └─────┘          │
                  │     ▲          ▲              │
                  │     │          │              │
                  │  ┌─────┐    ┌─────┐          │
                  │  │Auth │    │ API │──► S3    │
                  │  └─────┘    └─────┘          │
                  └──────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                 ▼
   ┌──────────┐    ┌──────────────┐   ┌──────────┐
   │ AGENT A  │    │  AGENT B     │   │ AGENT C  │
   │ Cap:     │    │  Cap:        │   │ Cap:     │
   │ forge    │    │  reach      │   │  bypass  │
   │ header X │    │  internal   │   │  auth    │
   └──────────┘    │  service    │   └──────────┘
                   └──────────────┘
          │                │              │
          └────────────────┼──────────────┘
                           ▼
                  ┌─────────────────┐
                  │   AGENT BUS     │
                  │  signal: chain  │
                  │  A.cap + B.cap  │
                  │  + C.cap = CRIT │
                  └─────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  REFUTATION     │
                  │  different      │
                  │  model tries    │
                  │  to KILL it     │
                  └─────────────────┘
                           │
                    ┌──────┴──────┐
                    ▼              ▼
              ┌──────────┐  ┌──────────┐
              │ SURVIVES │  │  KILLED  │
              │ → report │  │ → ledger │
              └──────────┘  └──────────┘
```

### 1. Capability Discovery (Not Vulnerability Scanning)

Each agent asks one question: **"What can I actually do here?"**

Not "Is this vulnerable to XSS?" but "Does my input reach the response?" Not "Is there an IDOR?" but "Can I access a resource that doesn't belong to me?"

The output of every agent is a list of capabilities — concrete, verifiable primitives:

| Capability | Evidence | Confidence |
|---|---|---|
| `param.redirect_url` controls `Location` header value | Response header mirrors input exactly | 100 |
| `POST /api/import` reaches `169.254.169.254` | SSRF returns AWS metadata | 100 |
| Auth header `X-Original-User` bypasses IAM check on `/admin` | Returns 200 for admin endpoints without session cookie | 90 |
| WebSocket upgrade carries auth cookies with no Origin check | Browser sends cookies on cross-origin WebSocket | 85 |

Each capability is logged to the **ledger** with exact evidence — the curl command, the response hash, the timestamp. Nothing is asserted without proof. The ledger is append-only and tamper-evident (JSONL + BLAKE3 hash chain per `chain_of_custody.py`). You cannot later claim you tested something you didn't test — the ledger either has the entry or it doesn't.

### 2. Trust Map Construction

While agents discover capabilities, a trust map is built from the target's architecture:

- **What trusts what?** The CDN trusts the app server's cache headers. The app trusts the auth service's user ID claim. The internal API trusts headers that the public API strips.
- **Where are the trust boundaries?** Public → Private. Authenticated → Admin. Service A → Service B.
- **What crosses boundaries?** A header set by the public API that's read by the internal API. A user ID from an IDOR that's accepted by a write endpoint. A redirect URL that lands in an OAuth callback.

The trust map is not static. Every new capability discovery updates it. When Agent A says "I can forge header X-Forwarded-For" and Agent B says "Internal dashboard trusts X-Forwarded-For for auth," the bus detects the trust boundary crossing and signals a chain candidate.

### 3. The Agent Bus — Autonomous Chain Building

Individual capabilities are low-severity or even expected behavior. The bus (`tools/agent_bus.py`) is what makes them dangerous.

Agents broadcast structured signals:

```
Signal(signal_type="discovery", from_agent="web-api-agent",
       to_agents=["*"], priority="medium",
       signal_data={"capability": "header_forge",
                    "param": "X-Original-User",
                    "endpoint": "/api/proxy",
                    "trust_boundary": "public-to-internal"})
```

The bus detects when two capabilities from different agents share a trust boundary:

- **Explicit chains:** Agent A emits `signal_type="chain"` connecting its capability to Agent B's.
- **Implicit chains:** Two discoveries targeting the same endpoint root with different methods (GET + PUT on `/users/:id` = read + write).
- **Trust map chains:** Any capability that crosses a trust boundary (public → internal, user → admin, service A → service B) is paired with capabilities on the other side.

23 predefined chain patterns ship in `kill_chain.py` (IDOR read→write, SSRF→metadata→RCE, OAuth redirect→ATO, etc.), but the bus also discovers **novel chains** by analyzing endpoint roots, trust boundary crossings, and auth→data pairings. Novel chains are what get you the bounties the checklist never finds.

### 4. Adversarial Refutation — Never Trust a Finding on Its Own Word

This is the core rule. **Every finding that comes out of the bus must survive a different model trying to kill it.**

The refutation model is given one instruction: *"Construct the strongest argument that this finding is wrong. Find the guard, check, or constraint that kills the attack. Quote the exact line and trace how it blocks the claimed step. You win if you kill the finding."*

This is not a review. This is an execution. The refutation model is adversarial — it has objective misalignment with the finding model. It wants the finding to fail.

The refutation runs the 4-gate evaluation from `references/judging.md`:

| Gate | Question | Fails if |
|---|---|---|
| **Gate 1 — Refutation** | Can a concrete guard block the claimed step? | Specific code path, check, or constraint kills it |
| **Gate 2 — Reachability** | Can the vulnerable state exist in a live deployment? | Structurally impossible (enforced invariant prevents it) |
| **Gate 3 — Trigger** | Can an unprivileged actor execute it profitably? | Only trusted role can trigger, or cost exceeds extraction |
| **Gate 4 — Impact** | Is there material harm to an identifiable victim? | Self-harm only, dust-level, non-compounding |

Speculative refutation ("probably wouldn't happen," "likely intended") does NOT kill a finding. Only concrete refutation with a specific guard and code trace kills it.

What survives all four gates is **confirmed**. What fails any gate is either **rejected** (dead) or **demoted to a lead** (code smell worth tracking but not yet a finding). What survives refutation but is uncertain becomes a **LEAD** — tracked, noted, but not reported until confirmed by another agent or a later pass.

### 5. The Ledger — Don't Lie to Yourself About What Actually Ran

The ledger (`tools/state.py` journal) records everything that actually happened:

```
journal.jsonl (append-only, tamper-evident):
{"ts": "2026-07-23T18:12:33Z", "event": "endpoint_tested",
 "data": {"url": "/api/users/1", "method": "GET", "status": 200,
          "content_hash": "a3f8b2c1...", "session_id": "d4e5f6a7"}}
{"ts": "2026-07-23T18:12:34Z", "event": "finding_added",
 "data": {"finding_id": "a1b2c3d4", "title": "IDOR on /api/users/:id"}}
{"ts": "2026-07-23T18:12:35Z", "event": "gate_evaluation",
 "data": {"finding_id": "a1b2c3d4", "gate": "refutation",
          "result": "cleared", "refutation_attempt": "no guard found"}}
```

The ledger is the truth. You cannot later inflate a finding's impact because the original evidence is hashed and immutable. You cannot claim you tested 200 endpoints when the ledger shows 47. The ledger doesn't care what you believe — it records what you did.

The **chain of custody** (`tools/chain_of_custody.py`) extends this with BLAKE3 content hashing and Merkle chain linking. Every evidence file is hashed and timestamped. Every custody entry links to the previous via hash. Tampering is cryptographically detectable.

### 6. Program-Fit Gate — Don't Bury a Report in Noise

After a finding survives refutation and the ledger confirms it, one more gate: **does this matter to this program?**

This is not about validity. A valid SQLi that dumps the entire database is still noise if the program's scope excludes the database tier. A perfect XSS on a sandbox domain is noise if the program doesn't accept cross-domain findings.

The program-fit gate checks:
- **Scope match:** Is the asset in scope for this program? (HackerOne, Bugcrowd, Immunefi all have scopes.)
- **Severity threshold:** Does the program pay for this severity level? (Some programs only pay medium+.)
- **Bug class acceptance:** Does the program accept this bug class? (Some don't pay for missing best practices, CSRF on logout, etc.)
- **Duplication check:** Has this exact finding (endpoint + bug class + parameter) already been found in this session?

Findings that fail the program-fit gate are **logged to the ledger** (because they're still true) but **NOT included in the report** (because they're noise). This is the same discipline as the ledger: don't lie to yourself about what will get paid, don't pad a report with informationals to make it look busy.

### 7. Why This Feels Illegal When It Runs

A normal audit runs one agent, one checklist, one pass. It produces a list of "potential issues" with medium confidence and a lot of "consider reviewings."

BountyForge v3 runs like this:

1. **8+ agents in parallel**, each hunting capabilities, not vulnerabilities.
2. **Every capability broadcast** across the agent bus. Other agents see it and update their own hunt.
3. **The trust map updates in real time.** When Agent A finds a header injection on the public API and Agent C finds that the internal admin panel trusts that header for authentication, the bus fires a chain signal **without any human noticing the connection**.
4. **A different model tries to refute every finding.** It constructs the strongest possible argument against it. It traces the code. It checks reachability. Only what survives is real.
5. **The ledger records everything.** You can't inflate, can't fabricate, can't bury bad results. What ran, ran. What didn't, didn't.
6. **Program-fit kills the noise.** Valid bugs that don't match the program scope are logged but silenced in the report.

A checklist auditor sees `?redirect_url=https://evil.com` and reports "Open Redirect — Low." BountyForge sees the same thing, checks the trust map, notices that the auth service accepts redirect_url as a valid OAuth callback, cross-references the agent bus signal from the auth agent that found a wildcard redirect_uri, chains them into "Open Redirect → OAuth Code Theft → Full Account Takeover — Critical," has a different model try to kill the chain, the chain survives, and it lands in the report at $15,000.

That's the difference. That's what the checklist can't do.

## Zero-Day Hunting Primitives

These are the capability classes BountyForge agents are taught to discover. Each is a primitive — not a vulnerability, but a building block that chains into one.

### Input Control Primitives
- **Parameter forge:** I can set any parameter value and the server accepts it
- **Header forge:** I can control a header value that downstream services read
- **Body forge:** I control the structure and content of a deserialized object
- **Method override:** I can change GET to PUT/DELETE via `_method`, `X-HTTP-Method-Override`
- **Content-type switch:** I can change how the server parses my input (JSON → XML → multipart)
- **Path segment control:** I control a URL path segment that gets used in routing or file operations

### Trust Boundary Primitives
- **Auth header passthrough:** Internal service trusts a header the public API strips
- **Origin reflection:** CORS echoes my Origin with credentials
- **Cookie scope leak:** Cookie set on parent domain is readable by subdomain
- **Redirect trust:** OAuth/SSO flow accepts a redirect URL controlled by a chained bug
- **IP-based trust:** Internal service trusts traffic from the app server's IP unconditionally
- **Internal DNS resolution:** Server resolves internal hostnames I can control or register

### Data Flow Primitives
- **Sink reach:** My input reaches an unsanitized sink (render, execute, query, write, eval, include)
- **Reflection point:** My input appears verbatim in the response
- **Persistence point:** My input is stored and later rendered without escaping
- **Deserialization point:** My serialized object is deserialized without type checking
- **Template injection point:** My input is interpolated into a template expression
- **Log injection point:** My input reaches a log that a log viewer interprets as markup

### Side-Channel Primitives
- **Timing oracle:** Response time varies with byte-by-byte guesses
- **Error oracle:** Error message reveals data (column names, file paths, internal IPs)
- **DNS oracle:** Server performs DNS lookup to attacker-controlled domain
- **HTTP callback:** Server makes HTTP request to attacker-controlled URL
- **Cache oracle:** Response caching behavior reveals data about other users' requests

### Infrastructure Primitives
- **Metadata reach:** SSRF reaches 169.254.169.254 or metadata.google.internal
- **Internal port open:** Server can connect to internal services on specific ports
- **File read primitive:** Path traversal allows reading arbitrary files
- **File write primitive:** Upload or import allows writing to arbitrary paths
- **Command primitive:** User input reaches `exec()`, `system()`, `popen()`, `subprocess`
- **CI/CD trigger:** Webhook or API call triggers a build or deploy pipeline

## The Chain Patterns That Ship

These are the chains that `kill_chain.py` auto-detects. Every one has been proven in real bug bounty reports ($500 → $50,000+):

| Chain | Primitives Combined | Typical Payout |
|---|---|---|
| IDOR read → write → delete | `param_forge` + `method_override` | $2,500–$15,000 |
| Open redirect → OAuth ATO | `redirect_trust` + `auth_header_passthrough` | $5,000–$30,000 |
| SSRF → metadata → RCE | `metadata_reach` + `command_primitive` | $10,000–$50,000 |
| Cache poison → stored XSS | `header_forge` + `reflection_point` + `persistence_point` | $5,000–$20,000 |
| HTTP smuggling → cookie exfil | `content_type_switch` + `cookie_scope_leak` | $3,000–$15,000 |
| Email bypass → SSO → ATO | `parameter_forge` + `redirect_trust` | $10,000–$50,000 |
| Prototype pollution → RCE | `body_forge` + `sink_reach` | $3,000–$20,000 |
| XXE → SSRF → internal pivot | `deserialization_point` + `internal_port_open` | $5,000–$30,000 |
| Mass assignment → admin | `parameter_forge` + `sink_reach` | $2,000–$15,000 |
| Deserialization → gadget → RCE | `deserialization_point` + `command_primitive` | $5,000–$30,000 |

## The Discipline

1. **Hunt capabilities, not vulnerabilities.** A vulnerability is what happens when capabilities chain. You can't find chains if you only look for finished bugs.

2. **Never trust a finding on its own word.** A different model must try to kill it. Only what survives adversarial refutation is real.

3. **The ledger is the truth.** Append-only. Tamper-evident. You cannot claim what you didn't do.

4. **Program-fit silences noise.** Valid bugs that don't match program scope are logged, not reported.

5. **Chains pay.** Single bugs are inputs. Chains are outputs. A low-severity capability that chains into critical impact is worth more than a standalone medium.

6. **Run it more than once.** LLM output is non-deterministic. Two passes = different capability discovery = different chains. Three passes is baseline.

7. **The trust map is a living document.** Every new capability updates it. Every chain candidate re-evaluates it. The map gets more dangerous the longer the audit runs.
