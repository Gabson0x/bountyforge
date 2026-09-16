# Recon, Credential Leaks & Source Recon

> Split from SKILL.md v4.1.0. Load at hunt start for any external target. Pipeline counterpart: `skills/web2-recon/SKILL.md`.

---

# PHASE 1: RECON

## Standard Recon Pipeline
```bash
# Step 1: Subdomains
subfaster -d TARGET -silent | anew /tmp/subs.txt
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

