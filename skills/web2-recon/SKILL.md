---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfaster, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), temp email creation for auth testing, deeper research techniques (disclosed reports, tech deep-dives, developer profiling), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping. Always go deeper — read disclosed reports, study the tech stack, create temp emails to test auth flows, map the full attack surface including hidden APIs and debug endpoints.
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting. **Always go deeper** — don't just enumerate, understand the target like its developers do.

---

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfaster with API keys for more sources (YAML format identical to subfinder)
mkdir -p ~/.config/subfaster
cat > ~/.config/subfaster/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfaster httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## TEMP EMAIL CREATION (Essential for Auth Testing)

Always create temp emails before hunting auth-related bugs. You need multiple accounts to test IDOR, privilege escalation, and auth bypass.

### Quick Temp Email Services

```bash
# 1. mail.tm API (free, no registration, programmatic)
# Create account via API — fastest for automation
create_temp_email() {
  DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')
  EMAIL="hunter_$(date +%s)@${DOMAIN}"
  PASSWORD="TempPass123!"
  curl -s -X POST https://api.mail.tm/accounts \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq .
  echo "$EMAIL" > /tmp/current_temp_email.txt
  echo "[+] Created temp email: $EMAIL"
}

# 2. guerrillamail.com (web-based, good for manual testing)
# Visit: https://www.guerrillamail.com/
# Or use API: curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_address"

# 3. tempmail.plus (clean interface, API available)
# Visit: https://tempmail.plus/

# 4. emailfake.com (multiple domain options)
# Visit: https://emailfake.com/

# 5. yopmail.com (persistent inboxes — good for long testing sessions)
# Visit: https://www.yopmail.com/
```

### Multi-Account Setup for IDOR/Privilege Testing

```bash
# Create 3 accounts with different "roles" for comprehensive testing
# Account A = attacker (low priv)
# Account B = victim (another user)
# Account C = admin (if you can get one)

for i in 1 2 3; do
  DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')
  EMAIL="test_user${i}_$(date +%s)@${DOMAIN}"
  PASSWORD="TestPass${i}!"
  curl -s -X POST https://api.mail.tm/accounts \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq .
  echo "Account $i: $EMAIL / $PASSWORD"
done
```

### Temp Email Workflow for Auth Testing

```
1. Create temp email -> register account on target
2. Verify email (fetch from temp email API)
3. Login, explore features, note all API calls
4. Create second temp email -> register second account
5. Test IDOR: Account A requests with Account B's IDs
6. Test privilege escalation: Account A tries admin endpoints
7. Test auth bypass: Access protected routes without token
8. Test password reset: Use temp email to receive reset links
9. Test email change: Does it require re-auth?
10. Test MFA: Create accounts with/without MFA enabled
```

### Password Reset Testing with Temp Emails

```bash
# 1. Create temp email
TEMP_EMAIL="test_$(date +%s)@$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')"

# 2. Register account with temp email
# 3. Trigger password reset for that email
# 4. Fetch reset token from temp email inbox
# 5. Test: Can you use the reset token from a DIFFERENT IP?
# 6. Test: Does the token expire? (request new one, try old one)
# 7. Test: Can you brute force weak tokens?
# 8. Test: Does the reset link leak in Referer header?
```

---

## DEEPER RESEARCH TECHNIQUES

**Never stop at surface-level recon.** Go deeper before you start hunting.

### Disclosed Reports Study (15 min minimum)

```bash
# 1. Read last 10 disclosed reports for this program on HackerOne
# Search: site:hackerone.com "PROGRAM_NAME" disclosed

# 2. Note patterns:
# - What bug classes got paid?
# - What endpoints were vulnerable?
# - What was the root cause?
# - What was the severity/payout?

# 3. Grep your target for the SAME anti-patterns found in disclosed reports
# If a report found IDOR on /api/v1/users/{id}, test /api/v2/users/{id}
# If a report found XSS in profile bio, test YOUR target's profile fields
```

### Tech Stack Deep-Dive (10 min)

```bash
# Don't just detect — UNDERSTAND the stack

# 1. Framework-specific attack surfaces:
# Laravel: /horizon, /telescope, /.env, /storage/logs/
# Django: /admin, /static/admin/, debug toolbar
# Express: /__debug__, /_health, /graphql introspection
# Spring Boot: /actuator/*, /swagger-ui.html
# Next.js: /_next/data/, /api/*, server components

# 2. Check framework VERSION for known CVEs:
# WordPress: /wp-json/wp/v2/users (version in headers)
# Drupal: /CHANGELOG.txt
# Joomla: /administrator/manifests/files/joomla.xml

# 3. Database-specific:
# MongoDB: check for /status, /dbStats endpoints
# Elasticsearch: /_cat/indices, /_cluster/health
# Redis: check if port 6379 is exposed

# 4. Cloud provider indicators:
# AWS: X-Amz-* headers, s3.amazonaws.com references
# GCP: storage.googleapis.com, metadata headers
# Azure: blob.core.windows.net, Azure-* headers
```

### Developer Profiling (5 min)

```bash
# Find the developers, learn their habits

# 1. GitHub org search
gh api /orgs/TARGET_ORG/repos --jq '.[].full_name' | head -20

# 2. Check commit patterns — who commits security-sensitive code?
git log --oneline --all --author="security\|auth\|middleware" | head -20

# 3. Check for .env files, config files in public repos
# Search: org:TARGET_ORG filename:.env
# Search: org:TARGET_ORG filename:config password

# 4. LinkedIn — find devs who work on auth/API features
# Their other projects may reveal coding patterns
```

### API Versioning Deep-Dive

```bash
# Many bugs hide in older API versions

# Test every version you find:
for v in v1 v2 v3 v4; do
  echo "=== Testing $v ==="
  curl -s "https://target.com/$v/users" -H "Authorization: Bearer $TOKEN" | head -100
  curl -s "https://target.com/$v/admin" -H "Authorization: Bearer $TOKEN" | head -100
done

# Common patterns:
# /api/v1/ — no auth, old endpoints still active
# /api/internal/ — debug endpoints exposed
# /api/beta/ — unreleased features with weaker security
# /graphql vs /graphiql — introspection might be enabled on one
```

### Hidden Parameter Discovery

```bash
# Standard recon finds visible params. Go deeper.

# arjun — finds hidden HTTP parameters
arjun -u "https://target.com/api/endpoint" -m GET,POST -o /tmp/hidden-params.json

# paramspider — mines parameters from web archives
paramspider -d target.com -o /tmp/paramspider.txt

# Also manually test:
# 1. JSON body params: {"debug": true}, {"admin": true}, {"bypass": true}
# 2. Custom headers: X-Debug, X-Forwarded-For, X-Original-URL
# 3. Cookie manipulation: role=admin, debug=true, impersonate=user_id
# 4. GraphQL variables: {"userId": 1, "admin": true}
```

### Sub-Resource Analysis

```bash
# Don't just find subdomains — understand what EACH one does

# Classify subdomains by function:
cat /tmp/live.txt | while read line; do
  host=$(echo $line | awk '{print $1}')
  # Check for:
  # - /api endpoints (API surface)
  # - /admin paths (admin panel)
  # - /debug or /actuator (debug interfaces)
  # - /graphql (GraphQL endpoint)
  # - /swagger or /docs (API documentation)
  # - File upload features
  # - Authentication flows (login, register, SSO)
done

# Priority subdomains to go deep on:
# - api.* or api-v2.* — main API surface
# - admin.* or internal.* — admin panels
# - staging.* or dev.* — debug environments
# - auth.* or sso.* — authentication systems
# - upload.* or cdn.* — file handling
# - mail.* or smtp.* — email systems (SSRF via email templates)
```

---

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfaster (passive multi-source)
subfaster -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt

# NEW: Additional vulnerability-specific paths
# SSRF candidates (webhooks, imports, PDF gen)
cat /tmp/urls.txt | grep -E "webhook|import|export|pdf|generate|preview|fetch|load|proxy" | tee /tmp/ssrf-candidates.txt

# SQLi candidates (search, filter, sort)
cat /tmp/urls.txt | grep -E "search|filter|sort|order|where|select|query|list" | tee /tmp/sqli-candidates.txt

# Command injection candidates
cat /tmp/urls.txt | grep -E "ping|nslookup|host|domain|url|ip|traceroute|diagnos" | tee /tmp/rce-candidates.txt

# File inclusion / path traversal candidates
cat /tmp/urls.txt | grep -E "include|require|file|path|template|page|view|load" | tee /tmp/lfi-candidates.txt

# WebSocket endpoints
cat /tmp/urls.txt | grep -E "ws://|wss://|socket|realtime|stream|live" | tee /tmp/ws-candidates.txt

# Deserialization candidates (Java/PHP/Ruby)
cat /tmp/urls.txt | grep -E "serialize|deserialize|object|data|session|cookie|marshal" | tee /tmp/deser-candidates.txt

# Sensitive data exposure
cat /tmp/urls.txt | grep -E "\.env|\.git|config|backup|dump|export|download|log" | tee /tmp/sensitive-paths.txt

# New feature endpoints (recently added = less tested)
cat /tmp/urls.txt | grep -E "beta|preview|new|experimental|alpha|canary" | tee /tmp/new-features.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
# Extended patterns (install from: https://github.com/KathanP19/gf-patterns)
cat /tmp/urls.txt | gf ssti | tee /tmp/ssti-candidates.txt
cat /tmp/urls.txt | gf debug_logic | tee /tmp/debug-candidates.txt
cat /tmp/urls.txt | gf secrets | tee /tmp/secrets-candidates.txt
cat /tmp/urls.txt | gf upload-fields | tee /tmp/upload-candidates.txt
cat /tmp/urls.txt | gf cors | tee /tmp/cors-candidates.txt
cat /tmp/urls.txt | gf json-params | tee /tmp/json-params.txt
cat /tmp/urls.txt | gf interesting-params | tee /tmp/interesting-all.txt
```

---

## JS ANALYSIS (Go Deep — This Is Where Hidden Bugs Live)

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

### Deep JS Taint Analysis (Manual — 15 min)

```bash
# Download ALL JS bundles
mkdir -p /tmp/js-deep
cat /tmp/urls.txt | grep "\.js$" | sort -u | head -100 | while read url; do
  fname=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "/tmp/js-deep/$fname" 2>/dev/null
done

# 1. Find ALL fetch/XMLHttpRequest/axios calls — these are API endpoints
grep -rn "fetch(\|axios\.\|\.get(\|\.post(\|\.put(\|\.delete(\|XMLHttpRequest" /tmp/js-deep/ | grep -v node_modules | tee /tmp/js-api-calls.txt

# 2. Find auth-related code — tokens, cookies, headers
grep -rn "Authorization\|Bearer\|token\|cookie\|session\|localStorage\|sessionStorage" /tmp/js-deep/ | tee /tmp/js-auth-code.txt

# 3. Find hardcoded secrets
grep -rn "api_key\|apiKey\|client_secret\|secret_key\|access_token\|private_key\|AWS_SECRET\|AKIA\|sk_live\|pk_live" /tmp/js-deep/ | tee /tmp/js-secrets.txt

# 4. Find admin/debug features
grep -rn "admin\|debug\|console\|internal\|dev\|staging\|test" /tmp/js-deep/ | grep -i "if\|role\|permission\|check\|bypass" | tee /tmp/js-admin-features.txt

# 5. Find dangerous sinks (for XSS/SSRF/RCE analysis)
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(\|setTimeout(\|new Function\|dangerouslySetInnerHTML" /tmp/js-deep/ | tee /tmp/js-dangerous-sinks.txt

# 6. Find WebSocket connections
grep -rn "WebSocket\|wss://\|ws://" /tmp/js-deep/ | tee /tmp/js-websockets.txt

# 7. Find URL construction (SSRF vectors)
grep -rn "new URL\|url\.href\|window\.location\|location\.href\|location\.assign\|location\.replace" /tmp/js-deep/ | tee /tmp/js-url-construction.txt

# 8. Find error handling that leaks info
grep -rn "catch\|\.catch\|onerror\|error\.message\|stack\|trace" /tmp/js-deep/ | tee /tmp/js-error-handling.txt

# 9. Find CORS configuration
grep -rn "cors\|Access-Control\|withCredentials\|cross-origin" /tmp/js-deep/ | tee /tmp/js-cors.txt

# 10. Find postMessage handlers (DOM XSS vectors)
grep -rn "postMessage\|addEventListener.*message\|onmessage" /tmp/js-deep/ | tee /tmp/js-postmessage.txt

echo "[+] JS deep analysis complete. Check /tmp/js-*.txt files"
```

---

## DIRECTORY FUZZING (Go Deeper — Find What Others Miss)

### ffuf — Standard Fuzzing

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR fuzzing with authenticated request
# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

### Deep Fuzzing Techniques (What Most Hunters Skip)

```bash
# 1. Technology-specific paths (based on detected stack)
# WordPress
ffuf -u "https://target.com/wp-content/FUZZ" -w ~/wordlists/wp-content.txt -ac -mc 200,301,302
ffuf -u "https://target.com/wp-json/wp/v2/FUZZ" -w ~/wordlists/wp-api.txt -ac

# Laravel
ffuf -u "https://target.com/storage/FUZZ" -w ~/wordlists/laravel-storage.txt -ac
ffuf -u "https://target.com/vendor/FUZZ" -w ~/wordlists/vendor-paths.txt -ac

# Node.js
ffuf -u "https://target.com/node_modules/.FUZZ" -w ~/wordlists/node-modules.txt -ac

# Spring Boot
ffuf -u "https://target.com/actuator/FUZZ" -w ~/wordlists/spring-actuator.txt -ac
ffuf -u "https://target.com/actuator/env" -mc 200  # always check env endpoint

# 2. Backup file discovery
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/backup-files.txt \
     -e .bak,.old,.orig,.save,.swp,.tmp,.copy,.backup \
     -mc 200 -ac

# 3. Hidden vhost discovery
ffuf -u "https://TARGET_IP/" \
     -H "Host: FUZZ.target.com" \
     -w ~/wordlists/subdomains-1000.txt \
     -ac -mc 200,301,302,403

# 4. Parameter discovery (hidden params)
ffuf -u "https://target.com/page?FUZZ=test" \
     -w ~/wordlists/burp-parameter-names.txt \
     -mc 200 -ac

# 5. JSON parameter fuzzing (POST body)
ffuf -u "https://target.com/api/endpoint" \
     -X POST -H "Content-Type: application/json" \
     -d '{"FUZZ":"test"}' \
     -w ~/wordlists/json-params.txt \
     -mc 200 -ac

# 6. Header fuzzing (find hidden endpoints via Host/Origin)
ffuf -u "https://TARGET_IP/" \
     -H "X-Forwarded-Host: FUZZ.target.com" \
     -w ~/wordlists/subdomains-1000.txt \
     -ac

# 7. Subdomain takeover check
ffuf -w ~/wordlists/subdomains-1000.txt -u https://FUZZ.target.com -ac -mc 200,301,302,403

# 8. Interesting file extensions
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -e .php,.asp,.aspx,.jsp,.py,.rb,.pl,.cgi,.conf,.cfg,.ini,.yaml,.yml,.json,.xml,.txt,.log,.sql,.bak,.old \
     -mc 200 -ac
```

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

### Deep Target Research (Before You Start Hunting)

```
READ THESE BEFORE TOUCHING ANY TOOL:
1. Program page — ALL in-scope assets, rules, safe harbor
2. Last 10 disclosed reports — what got paid, what didn't
3. CHANGELOG — what changed in last 30 days (new features = less tested)
4. GitHub repos — find code patterns, hardcoded secrets, developer habits
5. LinkedIn — who builds the auth/API features? What's their stack?
6. Tech stack docs — framework-specific attack surfaces
7. Status page — uptime history (incidents reveal internal architecture)
8. Blog posts — the company's own engineering blog reveals their stack
```

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfaster -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## PORT SCANNING (often skipped — don't skip)

```bash
# naabu — fast port scanner from ProjectDiscovery
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

## 30-MINUTE RECON PROTOCOL (Deeper Version)

### Minutes 0-5: Read Program Page + Deep Research

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
- READ last 10 disclosed reports for this program
- CHECK changelog for recent changes
- CHECK GitHub for public repos
- NOTE tech stack mentioned in reports
```

### Minutes 5-10: Create Temp Emails + Register Accounts

```bash
# Create 2-3 temp emails for multi-account testing
# Register accounts while recon runs in background
# This gives you auth-aware testing capability from minute 10

# Mail.tm API approach:
for i in 1 2 3; do
  DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')
  EMAIL="hunter${i}_$(date +%s)@${DOMAIN}"
  PASSWORD="HuntPass${i}!"
  curl -s -X POST https://api.mail.tm/accounts \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" > /dev/null
  echo "Account $i: $EMAIL / $PASSWORD"
done
```

### Minutes 10-15: Asset Discovery (Standard Pipeline)

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-20: Deep JS Analysis + Hidden Params

```bash
# Download and analyze ALL JS bundles (see JS Analysis section above)
# Run arjun for hidden parameter discovery
arjun -u "https://target.com/api/endpoint" -m GET,POST -o /tmp/hidden-params.json
# Check for API versioning (v1, v2, beta, internal)
```

### Minutes 20-25: Surface Map + Tech-Specific Hunting

```bash
# Run gf patterns and the interesting-params grep above
# Based on detected tech stack, run stack-specific checks:
# - Laravel: /horizon, /telescope, /.env
# - Spring: /actuator/env, /actuator/heapdump
# - WordPress: /wp-json/wp/v2/users, xmlrpc.php
# - Express: /__debug__, /graphql introspection
```

### Minutes 25-30: Manual Exploration + Auth Testing

```
Open Burp Suite. Browse the app with proxy on:
1. Register with temp email (email #1)
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list
5. Register second account (email #2) for IDOR testing
6. Test: can Account A access Account B's data?
7. Test: are there admin endpoints accessible to regular users?
8. Test: password reset flow with temp email
```

### After 30 min: Prioritize + Go Deep

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
Priority 6: New features (beta/preview) → less tested, more bugs
Priority 7: Webhook/callback endpoints → SSRF candidates
Priority 8: WebSocket endpoints → IDOR/injection candidates
Priority 9: Password reset/email flows → ATO candidates
Priority 10: Complex business logic (payment, coupon) → race condition candidates
```
