---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

# TRIAGE & VALIDATION

One wrong answer = STOP. Kill it. Move on.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

---

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

---

### Q2: Is the impact on the program's accepted impact list?

Go to the program page. Find "Vulnerability Types" or "Out of Scope."

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If your bug maps to a listed exclusion → KILL IT.**

---

### Q3: Is the root cause in an in-scope asset?

Confirm:
- Vulnerable domain is on the in-scope list (not `*.internal.target.com`)
- It's a production asset (not staging/dev unless explicitly in scope)
- It's not a third-party service the company just uses (not Stripe, Salesforce, Google Auth)

**If out-of-scope → KILL IT.**

---

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = centralization risk = **KILL IT** (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

---

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint name + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog/CHANGELOG.md — does it mention this behavior?
4. API docs / design docs — is it documented as intended?

**If acknowledged/design decision → KILL IT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- XSS → show actual cookie theft or session hijack, not just `alert(1)` or `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just DNS ping
- SQLi → show actual data exfil from a real table, not just error message
- IDOR → show actual other-user's data in response, not just a 200 status code

**If you can only show "technically possible" → DOWNGRADE severity, not kill.**

---

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list below. If it's on this list without a chain → **KILL IT.**

---

### Q8: Identity check — which session found this, and does it survive?

For any finding made under an authenticated hunt, record the answer to each:

```
1. Session ID:        [12-char BBHUNT_SESSION_ID hash from audit.jsonl]
2. Identity:          [low-priv user A / high-priv user B / API key / etc.]
3. Anonymous repro:   Does the same request work with NO auth header?
4. Cross-identity:    Does it work under session B with the same data scope?
5. Stale-cred repro:  Does a logged-out / expired session still get the data?
```

Why this matters:
- **IDOR / BOLA**: must work with session A reading session B's data — if it
  only works with no auth, that's "missing auth" not IDOR (different bug,
  different severity).
- **Priv-esc**: must work with low-priv session reading high-priv data — if
  both sessions can already see it, no bug.
- **Auth bypass**: must work *without* a valid session — if it stops working
  when you log out, you've found a permissions issue, not a bypass.
- **Always check both directions**: a finding that only reproduces under
  one identity is often a real, scoped permission boundary, not a vuln.

`audit.jsonl` entries are tagged with `session_id`. Re-run the request
under each identity and confirm the bug holds before writing the report.
This is the most common reason "confirmed IDOR" findings come back as N/A.

---

---

## ⛓️ 7-QUESTION GATE — SMART CONTRACT TRACK

For smart contract findings (EVM/Move/Solana), replace the web/general questions with these. All 7 must be YES.

### Q1 (SC): Can I exploit this RIGHT NOW with a working PoC?

Complete this template:
```
1. Setup:   [fork of deployed chain / local Anvil node / foundry test]
2. Trigger: [exact function calls, calldata, account — copy-paste ready forge test]
3. Result:  I can [steal / lock / desync / brick] [exact amount or invariant affected]
4. Impact:  The protocol consequence is [funds lost / invariant broken / permanent DoS]
5. Cost:    Time: [X minutes], Capital: [$0 / capital required for the attack]
```

**If you CANNOT write a passing `forge test` → KILL IT.**

---

### Q2 (SC): Is the triggerer someone the protocol does NOT intend to be the actor?

- "onlyOwner/governance can do X" = centralization risk = **KILL IT**
- "Any other party can do X that only the owner should do" = valid
- Trusted-actor trigger WITH a governance bypass = still valid
- Requires the attacker to already hold protocol admin keys = usually invalid

---

### Q3 (SC): Is impact concrete in protocol-native terms?

- Funds stolen or locked: state exact wei/token amounts + USD
- Accounting desync: name the exact invariant from code/docs it violates
- Oracle manipulation: show the real profit margin vs. manipulation cost
- Permanent DoS of someone's funds (locked forever, not just griefing)

**If you can only say "could lose funds" → KILL or DOWNGRADE to lead.**

---

### Q4 (SC): Is the contract version in scope and verified on-chain?

Confirm:
- Deployed on the listed chain (not testnet, not an old unpinned version)
- Source matches the verified Etherscan/Solscan bytecode
- Not `lib/`, `interfaces/`, `mocks/`, `*.t.sol`, `*Mock*`

**If out-of-scope file path or version → KILL IT.**

---

### Q5 (SC): Is this already known or accepted behavior?

Search:
1. Immunefi/Sherlock/Code4rena contest history for this protocol
2. ALL prior audit reports (`audits/` in repo, docs site)
3. CHANGELOG.md / README "known issues" / design docs
4. Prior bounty submissions (immunefi.com/vulnerabilities, program page)

**If acknowledged/known issue → KILL IT.**

---

### Q6 (SC): Is this on the contract always-rejected list?

- Theoretical / no working PoC → KILL
- Trusted-actor-only with no bypass → KILL
- View/read-only fn with wrong value, no downstream effect → KILL
- Admin backdoor behaving as documented → KILL
- MEV-dependence the protocol explicitly accepts → KILL unless profit clears documented slippage bounds
- Sub-$1 dust profit, no invariant broken → KILL (unless part of a chain)

---

### Q7 (SC): Would a DeFi-literate judge say "yes, that's a real bug"?

Read it as an Immunefi/Sherlock judge: quote the invariant, trace the exact
exploitable call path, show the PoC output. If the judge could argue "edge
case, working as intended" and you can't pre-kill that argument → **KILL.**

**Quick-kill rules:**
- No `forge test` PoC against a fork → DEMOTE to lead, not a finding
- `onlyOwner`/governance only trigger → KILL unless governance bypass shown
- Code in `lib/`/`interfaces/`/`mocks/`/`test/` → KILL
- "Docs say X but code does Y" → code is authoritative
- Old compiler, unreachable function → KILL (reachability before severity)

---

## COUNTER-PATTERNS — ANTI-REFUTATION RULES (from real misses)

These override the auto-kill reflexes above. Sourced from actual gate mistakes — do not repeat them.

**Gate 1 — "documented" / "matches upstream design" is NOT an automatic refutation:**
Rejecting on documentation requires actually having read the upstream source. Citing another protocol's behavior without seeing its code (e.g., "Camelot does the same with xGRAIL" while never opening Camelot's source) is a miss, not a defense. Docs describe intent; deployed bytecode is reality. To refute with "upstream," show the upstream code doing the same thing.

**Gate 2 — "requires oracle misreport" forces an honest-path check:**
Before rejecting a finding for relying on a misreporting oracle, check for an honest-path route to the same vulnerable state (e.g., the Lido `onchainTotalValueOnRefSlot` case — reachable with HONEST oracle data, making the "oracle manipulation" precondition unnecessary). Honest path exists → the finding stands WITHOUT the oracle caveat.

**Gate 3 — front-running a public state transition is attacker-triggerable, not "victim cooperation":**
"Requires the exiting holder's cooperation" is NOT an auto-kill when the state transition is public and observable on-chain (e.g., an xSilo `totalSupply → 0` after exit). The attacker front-runs the transition → attacker-triggerable. Precondition = a transaction the victim will unavoidably submit, not a deliberate action on their part.

**Gate 4 — split self-harm into actor-scoped legs:**
"Self-harm" often has SEPARATE victims per leg: the exiter's penalty loss is its own leg, the front-runner's captured residual is another leg. One self-inflicted leg does NOT kill the other leg's valid impact. Name the victim for EVERY leg before rejecting as "self-harm."

**Severity — "transient DoS" requires a confirmed self-resolving recovery path:**
Never call something "transient DoS" without confirming the recovery path exists and executes on its own (timelock expiry, guaranteed keeper, function any user can call to restore). Recovery dependent on a party that may never act, or unverified conditions → score as permanent DoS (or drop if no DoS is provable). Assumed recovery = inflated severity.

---

---

## 4 PRE-SUBMISSION GATES

Run in sequence. ALL 4 must PASS.

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked program scope page explicitly
[ ] Reproducible from scratch — can reproduce starting from fresh session
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## CVSS 3.1 QUICK REFERENCE

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

---

## KILL FAST RULES

The goal is to QUICKLY disqualify bad leads so you hunt real bugs:

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately
5. **Design doc test**: If it's documented behavior → kill it immediately
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters — is it actually sensitive?)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```
