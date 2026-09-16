# A→B Bug Chaining — H100 Proven Chains

> Split from SKILL.md v4.1.0. Load when cluster hunting or chaining primitives (single low/medium → high/critical). Signal method stays in SKILL.md.

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

