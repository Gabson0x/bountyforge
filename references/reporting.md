# Reporting — Defensive-Proof Format & Submission Rules

> Split from SKILL.md v4.1.0. Load when writing the report. Platform templates: `skills/report-writing/SKILL.md` + `references/report-formatting.md`.

---

# PHASE 5: REPORT

## Canonical Defensive-Proof Report Format

Every report MUST follow this exact structure to preempt triager rejection. See also `references/report-formatting.md`.

```
# <Target> Vulnerability Report
## <Descriptive, Non-Overclaimed Vulnerability Name>

---

## Scope & Engagement Gate
- **Engagement Context:** <BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest>
- **Target Asset:** <Exact domain, IP, repo, contract, or binary>
- **In Scope:** <Yes / N/A (Independent Research)>
- **Explicit Exclusions:** <Check program/vendor policy for excluded assets or classes; None if self-hosted/pentest>
- **Governing Rule / Policy:** <Quote program policy clause, security advisory terms, or Audit Rules of Engagement>
- **Impact & Boundary Threshold:** <Demonstrated security boundary crossed or business risk proven>
- **Evidence Supporting Eligibility:** <Concrete demonstrated observations proving impact>

**Severity:** <Critical | High | Medium | Low>
**Vulnerability Type:** <Primary CWE / Class>
**Affected Component:** <Component / Endpoint / Daemon Listener> (`<path/port/URL>`)
---

## Summary
<3–5 sentences. Covers: what the vulnerability is, where it lives, how it is triggered, and what an attacker gains. Explicitly state what is NOT claimed if scope/severity is sensitive. No hedging. Present tense.>

---

## Control Plane vs Unauthenticated Listener Architecture (Path A vs Path B)
- **Path A (Legitimate Intended Flow):** Requires valid authentication credentials (e.g. Bearer token, API key, OAuth state).
- **Path B (Unauthorized Flow Demonstrated):** Accepts equivalent operations directly without presenting any credential or authorization token.
- **Security Boundary Crossed:** <Explicit description of the authorization barrier bypassed>

---

## Absent Credential Evidence Grid
| Credential / Artifact | Present in Attack Request? | Verification Evidence |
|-----------------------|---------------------------|-----------------------|
| Authorization Header  | ❌ No | HEADERS frame contains only standard HTTP pseudo-headers |
| Bearer / API Token    | ❌ No | `/proc/self/environ` contains no TOKEN/KEY/SECRET variables |
| Session Cookie        | ❌ No | No Cookie header; cookie jar empty |
| Session File          | ❌ No | No token files in local filesystem or shared run directories |
| mTLS Certificate      | ❌ No | Connection opened over standard unauthenticated cleartext TCP / TLS |
| Capability Token      | ❌ No | No capability payload or signed request headers |

---

## Demonstrated vs. Inferred Audit Matrix
| Claim | Verification Status | Evidence / Reasoning |
|-------|--------------------|----------------------|
| <Target accepts unauthenticated request> | Demonstrated | <Executed request succeeded with zero headers> |
| <Execution context equals SDK capability> | Demonstrated | <Executed `id` returning same UID/GID as SDK> |
| <Guest isolation boundary crossed> | Demonstrated / Inferred | <Exact boundary verification> |
| <Host escape / system takeover> | Unproven | <Explicitly NOT claimed unless directly executed> |

---

## Root Cause
### 1. <Root cause label>
- <Tight bullet — one clause each, referencing exact code file / line / port>
- <No prose paragraphs>

---

## Steps to Reproduce
1. <Step 1: Context / setup>
2. <Step 2: Copy-pasteable curl or script>
3. <Step 3: Execute and observe response>

**Expected (if secure):** <What secure behavior / auth check should happen>
**Actual:** <What the vulnerable endpoint does>

---

## Proof of Concept (PoC)
### Step 1: <Short action label>
<sentence describing what this step demonstrates.>
[Screenshot or code block]

---

## Security Impact
- **Demonstrated Capability:** An attacker with <access level> can <exact action> without credentials.
- **Program Policy Threshold:** Meets program policy requirement by demonstrating <policy eligibility evidence>.

---

## Recommended Fix
1. <Actionable fix step 1 — e.g., enforce authentication on listener or bind to isolated interface>
2. <Actionable fix step 2>
```

### Format Rules (non-negotiable)
- **Zero fluff.** Every sentence must carry technical weight.
- **No hedging.** Never write "may", "could potentially", "it is possible that". If the code allows it, state it as fact.
- **Present tense throughout.**
- **H1** for the report title. **H2** for all top-level sections.
- **`---`** as divider after metadata strip and between major sections.
- No tables. No collapsible sections. No emoji.
- PoC steps: numbered, one-line action header (H3), one sentence of context, then screenshot or code block.

### Platform Adaptations

| Platform | Additional requirement |
|----------|----------------------|
| `h1` | Append CVSS 3.1 vector string as code block if `--cvss` |
| `immunefi` | Add **Asset Type**, **Blockchain/Tech Stack**, **Vulnerability Category** |
| `bugcrowd` | Use Bugcrowd severity labels (P1/P2/P3/P4) alongside plain label |
| `intigriti` | Add **Impact** tag field to metadata strip |

## Report Title Formula
```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```
**Good:** `IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data`
**Bad:** `IDOR vulnerability found`

## Impact Statement Formula
```
An [attacker with X access level] can [exact action] by [method], resulting in [business harm].
This requires [prerequisites] and leaves [detection/reversibility].
```

## Human Tone Rules (Avoid AI-Sounding Writing)
- Start sentences with the impact, not the vulnerability name
- Write like you're explaining to a smart developer, not a textbook
- Use "I" and active voice: "I found that..." not "A vulnerability was discovered..."
- One concrete example beats three abstract sentences
- No em dashes, no "comprehensive/leverage/seamless/ensure"

## The 60-Second Pre-Submit Checklist
```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or response body)
[ ] Two test accounts used (not just one account testing itself)
[ ] CVSS score calculated and included
[ ] Recommended fix is one sentence (not a lecture)
[ ] No typos in the endpoint path or parameter names
[ ] Report is < 600 words (triagers skim long reports)
[ ] Severity claimed matches impact described (don't overclaim)
```

## Severity Escalation Language
| Program Says | You Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account (no special role)" |
| "Limited impact" | "Affects [N] users / [PII type] / [$ amount]" |
| "Already known" | "Show me the report number — I searched and found none" |
| "By design" | "Show me the documentation that states this is intended" |
| "Low CVSS score" | "CVSS doesn't account for business impact — attacker can steal [X]" |

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

## ALWAYS REJECTED — Never Submit These

> **Wild-mode note:** this list kills standalone SUBMISSIONS, not hunting avenues. Every entry below has a chain partner (see "Conditionally Valid With Chain" below) — if you found one, find the partner before dropping it. Open redirect alone → N/A. Open redirect → OAuth code theft → ATO. The list is the chain menu, not a stop sign.

Missing CSP/HSTS/security headers, missing SPF/DKIM/DMARC, GraphQL introspection alone, banner/version disclosure without working CVE exploit, clickjacking on non-sensitive pages, tabnabbing, CSV injection, CORS wildcard without credential exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret in mobile app, SSRF DNS-ping only, host header injection alone, no rate limit on non-critical forms, session not invalidated on logout, concurrent sessions, internal IP disclosure, mixed content, SSL weak ciphers, missing HttpOnly/Secure cookie flags alone, broken external links, pre-account takeover, autocomplete on password fields.

---

## HIGH-VALUE TARGET PROFILES (From H100 Analysis)

Patterns extracted from 100 highest-upvoted HackerOne reports. Use for target selection and prioritization.

### Tier 1: Highest ROI Targets

**GitLab (12 reports, $134K total bounty)**
- Biggest attack surface of any program — code hosting, CI/CD, wiki, imports
- Top bug classes: RCE (4), File Read/Write (3), SSRF, Data Leak, SSTI
- Key attack surfaces:
  - **Project import** — SSRF, path traversal, file read via UploadsRewriter
  - **Markdown/Wiki rendering** — Kramdown RCE, stored XSS, template injection
  - **File uploads** — path traversal, webshell, ExifTool RCE
  - **CI/CD pipelines** — runner token exposure, pipeline job execution
  - **Merge requests** — code review features bypass file restrictions
- Hunting strategy: Focus on import/export features, check for path traversal in any file copy/move operation

**Shopify (8 reports, $50K total bounty)**
- Top bug classes: Privilege Escalation (4), SSRF, OAuth, Credential Leak, SSTI
- Key attack surfaces:
  - **Email confirmation flow** — bypass leads to full store takeover via SSO
  - **Electron apps** — .env files in packaged apps leak GitHub tokens
  - **Third-party apps** — OAuth misconfigurations in app integrations
  - **Stocky app** — OAuth token theft via redirect_uri manipulation
- Hunting strategy: Download all Shopify apps, extract .env from asar files, check OAuth flows

**PayPal (6 reports, $93.9K total bounty — highest $/report)**
- Top bug classes: XSS (2), RCE, Token Leak, DoS, IDOR
- Key attack surfaces:
  - **Login page** — cache poisoning → stored XSS on paypal.com/signin
  - **Security challenge flow** — token leaks email + plaintext password
  - **npm packages** — internal packages published to public registry
  - **Business management API** — IDOR on user management endpoints
- Hunting strategy: Focus on auth flows, cache poisoning, supply chain

**Snapchat (7 reports, $65K total bounty)**
- Top bug classes: Infrastructure Misconfig (3), RCE, Auth Bypass, SSRF
- Key attack surfaces:
  - **Internal tools** — Jenkins, Grafana, CI dashboards exposed
  - **Kubernetes** — API server exposed to internet, no auth
  - **Content management** — delete any user's spotlight content
  - **GraphQL** — information disclosure via introspection
- Hunting strategy: Scan for exposed admin panels, K8s APIs, internal dashboards

### Tier 2: Consistent Payouts

**Valve (5 reports, $40K)**
- Game client RCE (buffer overflow, XSS in chat), SQLi, payment tampering
- Attack surface: Steam client, game servers, report generation API
- Key: Client-side parsing of untrusted data (server info, chat messages)

**X / xAI (4 reports, $20.16K)**
- Pre-auth RCE via VPN (Pulse Secure 1-day), auth bypass, CRLF injection
- Attack surface: VPN infrastructure, Digits API, web properties
- Key: Monitor VPN vendor patches, test immediately after disclosure

**Uber (3 reports, $40.4K)**
- Info disclosure (bonjour.uber.com RPC), OAuth chain, leaked certificates
- Attack surface: Internal microservices, mobile APIs, OAuth flows
- Key: Check old/mobile API versions, leaked certs in git history

### Tier 3: Quick Wins

**Snapchat infrastructure** — Jenkins, Grafana, K8s API = instant $10-25K
**Starbucks** — SQLi on web apps + leaked credentials in repos = consistent findings
**Razer** — SQLi + command injection on gaming web portals
**Mail.ru** — SQLi, file upload, memory disclosure
**LY Corp (LINE)** — HTTP smuggling, OAuth misconfig, privilege escalation

### Cross-Target Patterns

| Attack Vector | Programs Hit | Avg Bounty |
|---------------|-------------|------------|
| Leaked tokens in code/apps | Shopify, Starbucks, Snapchat, Superhuman | $10-50K |
| HTTP smuggling → session hijack | Slack, LY Corp, Zomato, New Relic | $0-6.5K |
| Infrastructure misconfig (Jenkins/K8s) | Snapchat | $10-25K |
| GraphQL missing auth | HackerOne | $0-12.5K |
| Email confirmation bypass | Shopify | $0-15K |
| Cache poisoning → XSS | PayPal | $18-20K |
| File upload → RCE | Semrush, Starbucks, GitLab | $0-20K |
| npm/supply chain | PayPal, LY Corp | $11-30K |
| SQLi (classic) | Starbucks, Razer, Valve, Mail.ru, GSA | $0-25K |

## Conditionally Valid With Chain

| Low Finding | + Chain | = Valid Bug |
|------------|---------|-------------|
| Open redirect | + OAuth code theft | ATO |
| Clickjacking | + sensitive action + PoC | Account action |
| CORS wildcard | + credentialed exfil | Data theft |
| CSRF | + sensitive state change | Account takeover |
| No rate limit | + OTP brute force | ATO |
| SSRF (DNS only) | + internal access proof | Internal network access |
| Host header injection | + password reset poisoning | ATO |
| Self-XSS | + login CSRF | Stored XSS on victim |

---

## Safe Patterns (Do Not Flag)

**Smart contracts:** `unchecked` in Solidity 0.8+ with correct reasoning, explicit narrowing casts in 0.8+, MINIMUM_LIQUIDITY burn on first deposit, `SafeERC20`, `nonReentrant` (flag only cross-contract), two-step admin transfer, consistent protocol-favoring rounding without compounding.

**Web/API:** Rate limiting that genuinely prevents exploitation, CSRF tokens that are properly validated, self-XSS without escalation path, logout CSRF without session fixation, non-sensitive information disclosure (stack traces in dev mode only).

**Infrastructure/Nodes:** Unauthenticated operator RPC (ecosystem standard), plaintext local signer/CL↔EL communication, default bind to 0.0.0.0 (dev convenience), JWT without `exp` when `iat` freshness enforced, version/health endpoints without auth, no CORS headers on non-browser APIs.

**General:** Operator configuration parameters treated as attacker input, "add rate limiting" without amplification attack, "use checked_X instead of saturating_X" when upstream check exists, error messages containing HTTP status codes or generic library errors (not credentials/PII).

---
