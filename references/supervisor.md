# Supervisor — Finding Triage & Vetting System

The supervisor is the quality gate between raw scanner output and a submitted report. Every finding must pass through this triage pipeline before being written up. The supervisor is NOT a human — it is the agent's own critical reasoning applied systematically.

---

## Triage Pipeline Overview

```
Raw Finding → Gate 0 (Reality) → Gate 1 (Impact) → Gate 2 (Dedup) → Gate 3 (Quality) → Report
                                ↓ FAIL            ↓ FAIL          ↓ FAIL
                             KILL / DEMOTE      KILL / DEMOTE   KILL / DEMOTE
                OPEN LEAD (trigger proven, impact untraced) → persisted as a lead
                object in leads.jsonl with missing preconditions; mutated one
                variable at a time and retested next pass; parked leads stay
                in the chain pool (tools/leads.py)
```

---

## The 5-Step Methodology Spine

All triage and evaluation flows strictly follow this 5-step sequence:

```
Program Policy ──► Scope ──► Security Boundary ──► Demonstrated Impact ──► Severity
```

1. **Program Policy:** What are the exact terms, rules, and eligibility thresholds stated in the program policy?
2. **Scope:** Is the exact asset, subdomain, endpoint, repo, or binary listed as in-scope?
3. **Security Boundary:** What specific authorization check, isolation barrier, or trust assumption is crossed?
4. **Demonstrated Impact:** What capability was *proven* through direct execution (never inferred or assumed)?
5. **Severity:** What is the calibrated severity level derived strictly from demonstrated impact + program policy?

---

## Red Team Adversarial Triage Engine

Before drafting a report, BountyForge must **attack its own finding**. Switch mindsets to a hostile platform triager trying to reject the submission.

Run the **10 Red Team Attack Questions**:

1. **Scope:** Is the exact asset/function in scope?
2. **Policy:** Is this vulnerability class explicitly excluded?
3. **Precondition:** What does the attacker actually need?
4. **Authentication:** What credential/authorization is supposed to exist?
5. **Path A:** What is the legitimate intended flow?
6. **Path B:** What unauthorized flow was demonstrated?
7. **Boundary:** What security boundary is crossed?
8. **Impact:** What concrete capability does the attacker gain?
9. **Alternative explanation:** What is the strongest reasonable triager rebuttal?
10. **Evidence:** What observation defeats that rebuttal?

> **THE RED TEAM RULE:**
> **If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report.** Demote to an OPEN LEAD in `leads.jsonl`, mutate preconditions, or park it.

---

## Demonstrated vs. Inferred vs. Unproven Classification

To prevent report drift (e.g. inflating a "powerful guest execution primitive" into an "unproven sandbox host escape"), every claim in a finding MUST be categorized into an explicit verification status:

| Status Tag | Definition | Example |
|------------|------------|---------|
| **Demonstrated** | Verified directly via executed PoC with observable output | `ControllerService` accepts unauthenticated TCP connections; returns `uid=0` output |
| **Inferred** | Logically suggested by code structure or system architecture but not directly executed | User namespace isolation is active inside container based on `/proc/self/uid_map` |
| **Unproven** | Speculative impact requiring unexecuted exploits or unverified preconditions | User namespace permits host kernel escape; host compromise achieved |

### Drift Audit Matrix (Run Before Report Writing)

```markdown
| Claim | Status | Verification Evidence / Reason |
|-------|--------|---------------------------------|
| Target endpoint accepts unauthenticated requests | Demonstrated | TCP connect + h2c request succeed with zero headers |
| SDK credential isn't supplied | Demonstrated | No TOKEN/KEY header, `/proc/self/environ` clean |
| Execution context equals SDK capability | Demonstrated | Executed `id; uname -a` returning same UID/GID as SDK exec |
| User namespace gives root inside container | Demonstrated | `id` returns `uid=0(root)` inside guest namespace |
| User namespace permits host escape | Inferred / Unproven | No host-side execution demonstrated |
| Host compromise achieved | Unproven | No host-side read/write demonstrated |
| Critical severity claimed | Unproven | Severity MUST be calibrated to demonstrated primitive only |
```

---

## Scope & Engagement Gate

BountyForge supports three engagement modes depending on how the hunt is conducted:

| Engagement Mode | Context & Target | Scope Source | Primary Goal |
|-----------------|------------------|--------------|--------------|
| **Bug Bounty Platform (BBP / VDP)** | HackerOne, Bugcrowd, Intigriti, Immunefi | Program Policy Page & Rules | Policy compliance, platform triage pass, bounty reward |
| **Direct Vendor / Independent Research** | Security advisory, private disclosure, open-source | Vendor Security Policy / Security Boundary | Responsible disclosure, vendor security advisory, patch verification |
| **Internal Red Team / Pentest / Audit** | Corporate network, codebase audit, internal target | Rules of Engagement / Audit Scope | System hardening, risk assessment, executive report |

```markdown
## Scope & Engagement Gate

- **Engagement Context:** [BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest]
- **Target Asset:** [Exact domain, IP, repo, contract, or binary]
- **In Scope:** [Yes / N/A (Independent Research)]
- **Explicit Exclusions:** [Check program/vendor policy for excluded assets or classes; None if self-hosted/pentest]
- **Governing Rule / Policy:** [Quote program policy clause, security advisory terms, or Audit Rules of Engagement]
- **Impact & Boundary Threshold:** [Demonstrated security boundary crossed or business risk proven]
- **Evidence Supporting Eligibility:** [Concrete demonstrated observations proving impact]
```

### Scope & Policy Derivation Rules

1. **Platform Hunts (BBP / VDP):** Extract explicit policy terms. Verify asset is listed in-scope and vulnerability class is not excluded.
2. **Direct Vendor / Independent Research:** Verify target belongs to vendor infrastructure/software. Ensure research adheres to standard safe-harbor / vulnerability disclosure guidelines.
3. **Internal Pentest / Red Team:** Align finding to engagement Rules of Engagement (RoE) and technical risk impact.

---

## Defensive-Proof Wording & Anti-Triager Blueprint

Triagers look for reasons to reject. Eliminate their arguments before they type them:

### 1. Path A (Intended) vs Path B (Unintended) Framing

When reporting unauthenticated access to a daemon, API, or listener:
- **Path A (Authenticated / Intended Flow):** Show that the primary control plane *requires* authentication (API key, OAuth, Bearer token).
- **Path B (Unintended / Unauthorized Flow):** Show that the secondary / internal listener accepts equivalent operations *without* presenting any credential.
- **Boundary Crossed:** Contrast Path A and Path B to prove an unauthenticated bypass of the intended control plane authorization barrier.

### 2. Absent Credential Evidence Grid (Mandatory for Unauth Findings)

Every unauthenticated vulnerability report MUST include an explicit evidence table:

```markdown
| Credential / Artifact | Present in Attack Request? | Verification Evidence |
|-----------------------|---------------------------|-----------------------|
| Authorization Header  | ❌ No | HEADERS frame contains only standard HTTP pseudo-headers |
| Bearer / API Token    | ❌ No | `/proc/self/environ` contains no TOKEN/KEY/SECRET variables |
| Session Cookie        | ❌ No | No Cookie header; cookie jar empty |
| Session File          | ❌ No | No token files in local filesystem or shared run directories |
| mTLS Certificate      | ❌ No | Connection opened over standard unauthenticated cleartext TCP / TLS |
| Capability Token      | ❌ No | No capability payload or signed request headers |
```

### 3. Overclaim Prevention Table

| Overclaimed Title (Triggers Triager Rejection) | Bulletproof Defensive Title (Triager Accepts) |
|-----------------------------------------------|-----------------------------------------------|
| "Host Escape / Container Breakout in Sandbox" | "Unauthenticated `ControllerService` Listener Exposes Command Execution to Guest Workload Processes" |
| "Full Account Takeover via API" | "IDOR in `/api/v2/users/{id}/email` Allows Authenticated User to Modify Secondary Account Email" |
| "Remote Code Execution via File Upload" | "Arbitrary File Upload to Web-Accessible Directory Enables Script Execution in Web Server Context" |
| "Authentication Bypass in OAuth Flow" | "Missing `state` Validation in `/oauth2callback` Enables Cross-Site Request Forgery (Login CSRF)" |

---

## Gate 0: Reality Check (30 seconds)

The finding must be REAL — confirmed with actual HTTP requests or code execution, not speculation from reading code.

### Required Evidence (at least ONE must be present)

| Evidence Type | What Counts | What Doesn't |
|--------------|-------------|--------------|
| HTTP response | Full request + response with status code and body | "The server would probably..." |
| Screenshot | Shows actual impact (changed data, exposed PII) | Screenshot of a form field existing |
| Code trace | Exact line numbers showing unguarded path | "This pattern is dangerous in general" |
| Reproduction | Same result from 2+ different starting states | "It worked once but I can't reproduce" |

### Fail Conditions (KILL immediately)
- "I read the code and it looks like..." — no live confirmation
- "This type of endpoint is often vulnerable to..." — pattern matching without testing
- "The response was different so there might be..." — ambiguous signal
- Only tested with your own data (IDOR needs cross-account proof)
- Tested on a dev/staging environment not in scope

### Demote Conditions
- Finding is real but only on a non-production environment explicitly out of scope → DEMOTE to note, do not report
- Finding requires a specific browser/OS version → note the constraint

---

## Gate 1: Impact Validation (2 minutes)

### The Impact Litmus Test

Answer this question with a single concrete sentence:

> "An attacker can __________, resulting in __________."

The first blank must be a specific action. The second must be a specific harm.

**PASSES:**
- "An attacker can read any user's booking confirmation emails, resulting in exposure of full traveler PII including passport numbers."
- "An attacker can redeem the same gift card 50 times concurrently, resulting in $5,000 theft from a $100 card."
- "An attacker can write arbitrary telemetry to the production Azure App Insights instance, resulting in false SOC alerts and masked real attacks."

**FAILS (kill immediately):**
- "An attacker can potentially access data" — what data? whose?
- "An attacker could theoretically..." — theoretically is not a finding
- "This could be used in a chain" — build the chain first, then report
- "This is a security misconfiguration" — describe the actual harm, not the category
- "This violates best practice" — best practice violations without exploit impact are not bugs

### Trigger vs Impact — the two-halves rule (read before ANY kill)

The Impact Litmus Test answers ONE half of every lead. A kill is legal only
after BOTH halves are resolved:

- **Q-TRIGGER** — "Can the path fire?" If refuted (unreachable, trusted-actor-only with no bypass) → KILL.
- **Q-IMPACT** — "If it fires, what does the VICTIM lose?" If untraced → **DEMOTE to OPEN LEAD**, not KILL. The lead becomes a persistent research object (`tools/leads.py`): decompose the block into named missing preconditions, mutate one variable at a time until impact is provable, and keep the payload. If it still cannot prove impact, PARK it into the chain pool — never drop it. A kill without BOTH refutations is refused by the ledger and auto-parks instead.

**Conflation is the failure mode.** Answering "can it fire?" and moving on
because the impact "seems below the bar" is the mistake this gate exists to
prevent. And impact is victim-harm, not attacker-profit: "this doesn't make an
attacker money" refutes nothing — an accounting desync that strands or
misdirects account value is account-owner loss, a Medium floor on Immunefi on
its own. Whether it chains into attacker profit is a separate trace, never a
precondition for keeping the lead alive. Severity estimation never precedes
the impact trace.

### Impact Tiers

| Tier | Impact | Examples | Severity Floor |
|------|--------|----------|----------------|
| T0 | Critical | RCE, auth bypass → admin, cloud credential theft, fund drain | Critical (9.0+) |
| T1 | High | PII/PHI exposure, ATO, financial manipulation, data destruction | High (7.0+) |
| T2 | Medium | Non-sensitive data exposure, limited IDOR (read-only, non-PII), stored XSS on low-value page | Medium (4.0+) |
| T3 | Low | Info disclosure (non-sensitive), missing security headers, clickjacking on static page | Low (0.1+) |
| T4 | None | CSP report-only, banner version without exploit, self-XSS, logout CSRF | Informational (0.0) — DO NOT REPORT |

### Common Impact Inflation (reject these)

| Claim | Reality |
|-------|---------|
| "Session hijacking" via XSS | Is HttpOnly set? If yes, you can't steal the session cookie. |
| "Account takeover" via open redirect | Do you have a full OAuth chain? If not, it's just an open redirect. |
| "Data breach" via API exposing counts | A count is not a breach. You need actual PII/credentials. |
| "RCE" via file upload | Did you actually execute code on the server? Or just upload a .php file to a static CDN? |
| "Denial of service" via one slow request | Can you actually take the service offline? If the request just times out, that's not DoS. |

---

## Gate 2: Deduplication Check (5 minutes)

### Step 1: Search Disclosed Reports

```bash
# HackerOne Hacktivity
curl -s "https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+BUG_CLASS"

# GitHub issues for the target
gh search issues "security" --repo OWNER/REPO --limit 20

# Public disclosures
site:hackerone.com/PROGRAM "KEYWORD"
```

### Step 2: Check These Sources

- [ ] HackerOne Hacktivity for this program (last 90 days)
- [ ] Bugcrowd Crowdstream for this program
- [ ] Program's public changelog / release notes
- [ ] GitHub Issues for the target repo (search: "security", "vuln", bug class name)
- [ ] The program's "known issues" or "out of scope" page
- [ ] Google: `site:target.com "security" "fixed"`

### Step 3: Duplicate Decision

| Situation | Action |
|-----------|--------|
| Same endpoint, same bug class, same impact → exact duplicate | KILL |
| Same endpoint, different bug class → not a duplicate | CONTINUE |
| Different endpoint, same bug class and root cause | Group into ONE report mentioning all affected endpoints |
| Same bug but your impact is significantly higher | REPORT with escalation language |

---

## Gate 3: Report Quality (10 minutes)

### Title Quality

The title must contain: **vuln class + location + attacker role + impact + victim scope**.

```
FORMAT: [Bug Class] in [Exact Endpoint] allows [attacker] to [action] [victim]
GOOD:   IDOR in /api/v2/bookings/{id} allows any authenticated user to read any traveler's passport data
BAD:    IDOR vulnerability found
BAD:    Possible authorization issue in booking API
```

### PoC Quality

The PoC must be:
1. **Copy-pasteable** — the triager can run your curl command and see the same result
2. **Self-contained** — no "set up a VPS first" or "install this toolchain"
3. **Minimal** — the shortest sequence that demonstrates the impact
4. **Reproducible** — works every time, not just once

### Evidence Quality

- Screenshots must show the impact, not just the request
- For IDOR: show victim's data accessed from attacker's session
- For XSS: show the alert popup OR DOM manipulation result
- For SSRF: show the callback received OR metadata response
- For race conditions: show both successful responses

### Impact Statement Quality

Must answer ALL of:
1. What can the attacker do? (specific action)
2. To whom? (identifiable victim — user, company, system)
3. What's the worst case? (quantify: $ amount, number of users, type of data)
4. What does the attacker need? (nothing, free account, paid account, admin approval)
5. Is it detectable? (audit log? alert? or silent?)

---

## False Positive Patterns (Common Mistakes)

### Pattern 1: Missing Auth Header Returns Different Status
```
GET /api/admin/users → 401 (expected: auth required)
GET /api/admin/users -H "Authorization: Bearer USER_TOKEN" → 200 (expected: user list)
```
If 401 without token, auth IS working. The lack of 403 for user token might be a finding, but 401 without token is correct behavior.

### Pattern 2: Parameter Reflection Without Execution
```
GET /search?q=<script>alert(1)</script> → Response contains: <script>alert(1)</script>
```
Reflection alone is not XSS. Is it reflected in HTML context without encoding? In a JSON string? In a header? Context matters.

### Pattern 3: CORS Reflects Origin Without Credentials
```
Origin: https://evil.com → Access-Control-Allow-Origin: https://evil.com
```
If `Access-Control-Allow-Credentials: true` is NOT present, this is not exploitable for credentialed data theft.

### Pattern 4: CSP Report-Only
A `content-security-policy-report-only` header DOES NOT block anything. It only reports violations. This is not a finding unless the report-uri is attacker-controllable.

### Pattern 5: Rate Limiting "Bypass" That Doesn't Scale
If you need 100 different IP addresses to bypass rate limiting, and the harm requires 10,000 requests... that's not a practical attack.

---

## Severity Escalation Pattern

When a triager pushes back with a lower severity, use these counter-arguments:

| Triager Says | You Respond |
|-------------|-------------|
| "This requires authentication" | "Authentication requires only a free account — no special role, no approval, no payment. The program's threat model includes malicious authenticated users." |
| "The impact is limited to one user" | "The attack is repeatable against ALL users. An attacker can enumerate every user ID and exfiltrate all PII. This is not one victim — it's the entire user base." |
| "This is by design" | "Please point me to the documentation that states users should be able to access other users' private data. If this is intended, it's not documented." |
| "The CVSS score is lower" | "CVSS doesn't capture business context. This endpoint exposes passport numbers — regulatory fines for PII exposure exceed $X. The business impact is higher than the technical score." |
| "We already know about this" | "Can you share the internal ticket ID or previous report number? I searched disclosed reports and found nothing." |
| "This is informational" | "I can demonstrate actual data exposure (see PoC). Informational findings don't have demonstrable impact — this does." |

---

## Triage Decision Tree (Quick Reference)

```
Finding received:
│
├─ Is it confirmed with a real HTTP request?
│  └─ NO → KILL
│
├─ Does it affect a real victim with real harm?
│  └─ NO → KILL
│
├─ Is the harm one of: money stolen, PII leaked, ATO, RCE, data destruction?
│  └─ NO → DEMOTE to informational or KILL
│
├─ Is the endpoint in scope?
│  └─ NO → KILL (or note as out-of-scope lead)
│
├─ Has this exact bug been reported before?
│  └─ YES → KILL (duplicate)
│
├─ Is this on the "always rejected" list?
│  └─ YES and no chain → KILL
│
├─ Can a triager reproduce this from my PoC in under 5 minutes?
│  └─ NO → Improve PoC before submitting
│
└─ All checks pass → WRITE REPORT
```

---

## Batch Triage Mode

When given a list of findings (from a scan, another tool, or manual testing), triage in this order:

1. **Group** — cluster by endpoint/feature. Same endpoint bugs go together.
2. **Sort** — highest impact first. T0 before T1 before T2.
3. **Dedup within batch** — if findings #3 and #7 are the same root cause, merge them.
4. **Gate each** — run each unique finding through all 4 gates.
5. **Output** — three lists: CONFIRMED (ready for report), LEADS (needs more testing), KILLED (dead ends).

### Batch Output Format

```markdown
## Triage Results — [Target] — [Date]

### CONFIRMED (Ready for Report)
| # | Title | Severity | CVSS | Confidence |
|---|-------|----------|------|------------|
| 1 | IDOR in /api/bookings/{id} — read traveler PII | High | 7.5 | 90 |
| 2 | Race condition in /redeem — double-spend gift cards | Critical | 9.0 | 85 |

### LEADS (Needs More Testing)
| # | Description | What's Missing |
|---|-------------|----------------|
| 1 | /api/export returns 200 without auth cookie — possible unauth data export | Need to confirm what data is returned |
| 2 | GraphQL introspection enabled — field-level auth may be missing | Need to test node() queries across types |

### KILLED (Do Not Revisit)
| # | Description | Kill Reason |
|---|-------------|-------------|
| 1 | Missing CSP header | Always rejected — no exploit impact |
| 2 | Cloudflare blocks POST without cookie | Working as intended — WAF doing its job |
```

---

## Integration with SKILL.md

The main SKILL.md Phase 4 (Validate) references this supervisor. The 7-Question Gate is the quick version. This document is the detailed version. Use the 7-Question Gate for fast triage during hunting; use this full supervisor for findings you intend to report.
