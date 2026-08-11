# BountyForge CWE Knowledge Base — 1000+ CWEs

Organized by agent domain for lazy-loading. Each CWE entry includes: ID, name, owning agent, severity range, detection pattern, and impact.
Load only the sections relevant to the active mode. Full file: load sections matching spawned agents only.

> **Source:** MITRE CWE v4.16 + NVD/NIST mappings + OWASP Top 10 + SWC Registry (smart contracts) + CWE Top 25 Most Dangerous

---

## CWE-1: Web/API Injection (agent: web-api-agent) — ~180 CWEs

### SQL Injection Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-89 | SQL Injection | Critical | `' OR 1=1--`, error-based, UNION SELECT, time-delay | Full DB access, data exfil, RCE via xp_cmdshell |
| CWE-564 | SQL Injection: Hibernate | Critical | HQL/JPQL injection in named queries | Same as CWE-89 via ORM |
| CWE-943 | NoSQL Injection | Critical | `{"$gt":""}`, `{$ne:null}`, regex injection in MongoDB/CouchDB | Auth bypass, data exfil |
| CWE-652 | XQuery Injection | High | XML query parameter injection | XML DB compromise |
| CWE-91 | XML Injection (Blind XPath) | High | `' or '1'='1` in XPath queries | XML data exfil |

### Command Injection Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-77 | Command Injection | Critical | `;id`, `|whoami`, `` `cmd` ``, `$(cmd)` in system calls | RCE on host |
| CWE-78 | OS Command Injection | Critical | Unsanitized input to system()/exec()/popen()/Runtime.exec() | Full server compromise |
| CWE-88 | Argument Injection | High | `--help`, `-n`, extra flags injected into CLI args | File read/write, RCE |
| CWE-624 | Executable Regular Expression | Medium | User-controlled regex patterns (ReDoS + potential code exec) | DoS, code exec |

### Code Injection Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-94 | Code Injection | Critical | `eval()`, `Function()`, `require()` with user input | Full RCE |
| CWE-95 | Eval Injection | Critical | Direct eval of user-supplied strings | RCE |
| CWE-96 | Static Code Injection | Critical | User input written to interpreted files (PHP, Python, JS) | RCE on include/import |
| CWE-1336 | Formula Injection (CSV Injection) | High | `=cmd|' /C calc'!A0`, `@SUM(1,2)` in CSV export | RCE when opened in Excel |
| CWE-98 | PHP Remote File Inclusion | Critical | `include($_GET['page'])` with remote URL | RCE |
| CWE-473 | PHP External Variable Modification | High | Register globals, extract() on user input | Variable poisoning |
| CWE-621 | Variable Extraction Error | Medium | extract() with EXTR_OVERWRITE | Variable manipulation |
| CWE-627 | Dynamic Variable Evaluation | High | `$$var` in PHP with user-controlled variable names | Variable manipulation |

### Template Injection Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-1336 | Server-Side Template Injection (SSTI) | Critical | `{{7*7}}`, `${7*7}`, `{{config}}` in templates | RCE, file read, SSRF |
| CWE-94 | Client-Side Template Injection | High | `{{constructor.constructor('alert(1)')()}}` in AngularJS/Vue | XSS, client-side RCE |

### Path Traversal Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-22 | Path Traversal | High | `../../../etc/passwd`, `..\..\windows\win.ini` | File read, source disclosure |
| CWE-23 | Relative Path Traversal | High | `../../` without root anchor | File read |
| CWE-35 | Path Traversal: '.../...//' | Medium | Triple-dot variant bypass | File read |
| CWE-36 | Absolute Path Traversal | High | `/etc/passwd` directly supplied | File read |
| CWE-37 | Path Traversal: '/absolute/path/here' | Medium | Forward-slash absolute path | File read |
| CWE-38 | Path Traversal: '\absolute\path\here' | Medium | Backslash absolute path | File read |
| CWE-39 | Path Traversal: 'C:dirname' | Medium | Windows drive-relative path | File read |
| CWE-40 | Path Traversal: '\\UNC\share\name\' | High | UNC path injection on Windows | File read, hash capture |
| CWE-41 | Path Equivalence: '/./' (single dot) | Low | Filter bypass using /./ in path | File read bypass |
| CWE-42 | Path Equivalence: '/./' (double dot) | Low | Filter bypass using /../ sequences | File read bypass |
| CWE-43 | Path Equivalence: 'filename....' | Low | Trailing dots on Windows | File upload bypass |
| CWE-44 | Path Equivalence: 'file.name' (trailing space) | Low | Trailing space bypass on Windows | File upload bypass |
| CWE-45 | Path Equivalence: 'file...' (multiple trailing dot) | Low | Multiple trailing dots | Filter bypass |
| CWE-46 | Path Equivalence: 'file ' (trailing space) | Low | Trailing space in filename | Filter bypass |
| CWE-47 | Path Equivalence: ' file' (leading space) | Low | Leading space in filename | Filter bypass |
| CWE-48 | Path Equivalence: 'file.json/' (trailing slash) | Low | Trailing slash on filename | Filter bypass |
| CWE-49 | Path Equivalence: 'folder/folder/..' | Low | Internal dot-dot on directory | Filter bypass |
| CWE-50 | Path Equivalence: '//multiple/leading/slash' | Low | Double leading slash | Filter bypass |
| CWE-51 | Path Equivalence: '/./././' (multiple dot) | Low | Repeated single-dot with slash | Filter bypass |
| CWE-52 | Path Equivalence: '/ equivalente ' (trailing) | Low | Trailing equivalent path | Filter bypass |
| CWE-53 | Path Equivalence: '\multiple\internal\backslash' | Low | Multiple internal backslash | Filter bypass |
| CWE-54 | Path Equivalence: 'filedir\' (trailing backslash) | Low | Trailing backslash | Filter bypass |
| CWE-55 | Path Equivalence: '/./' (single dot directory) | Low | Single dot directory | Filter bypass |
| CWE-56 | Path Equivalence: 'filedir*' (wildcard) | Low | Wildcard character in path | Filter bypass |
| CWE-57 | Path Equivalence: 'fakedir/../file' | Low | Dot-dot after fake directory | Filter bypass |
| CWE-58 | Path Equivalence: '%00' (null byte) on Windows | Medium | Null byte injection in path | Filter bypass |
| CWE-59 | Symlink Following | Medium | Symlink pointing outside web root | File read via symlink |

### Deserialization Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-502 | Deserialization of Untrusted Data | Critical | Java ObjectInputStream, Python pickle, PHP unserialize, .NET BinaryFormatter | RCE, DoS, auth bypass |
| CWE-915 | Dynamically-Manipulated Deserialization | High | Reflection-based deserialization abuse | RCE, type confusion |
| CWE-913 | Improperly Controlled Modification of Dynamically-Managed Code Resources | High | Runtime code modification | Code exec |

### XXE Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-611 | XML External Entity (XXE) | Critical | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | File read, SSRF, DoS |
| CWE-827 | Improper Control of Document Type Definition | Critical | DTD manipulation in XML parser | XXE, DoS via billion laughs |
| CWE-776 | XML Entity Expansion (Billion Laughs) | Medium | Recursive entity definition DoS | Service DoS |

### Memory Corruption Family
| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-120 | Buffer Overflow (Classic) | Critical | `strcpy()`, `gets()`, `sprintf()` without bounds | RCE, DoS |
| CWE-121 | Stack-Based Buffer Overflow | Critical | Stack buffer + unchecked copy | RCE |
| CWE-122 | Heap-Based Buffer Overflow | Critical | Heap buffer + malloc + overflow | RCE |
| CWE-123 | Write-What-Where Condition | Critical | Arbitrary write primitive | RCE |
| CWE-124 | Buffer Underflow | High | Under-indexing buffer | Memory corruption |
| CWE-125 | Out-of-bounds Read | High | Reading past buffer end (Heartbleed) | Info disclosure |
| CWE-126 | Buffer Over-read | Medium | Reading beyond buffer | Info disclosure |
| CWE-127 | Buffer Under-read | Medium | Reading before buffer | Info disclosure |
| CWE-128 | Wrap-around Error | High | Integer wrap in size calculation | Buffer overflow |
| CWE-129 | Improper Validation of Array Index | High | Unchecked index into array | Arbitrary R/W |
| CWE-130 | Improper Handling of Length Parameter Inconsistency | Medium | Length mismatch between components | Overflow |
| CWE-131 | Incorrect Calculation of Buffer Size | High | sizeof() mistakes, off-by-one in allocation | Overflow |
| CWE-134 | Uncontrolled Format String | Critical | `printf(user_input)` without format specifier | RCE, info leak |
| CWE-135 | Incorrect Calculation of Multi-Byte String Length | Medium | wchar/multibyte length miscalculation | Buffer overflow |
| CWE-170 | Improper Null Termination | Medium | String missing null terminator | Info leak |
| CWE-190 | Integer Overflow/Wraparound | High | `int_max + 1 = int_min` in allocation math | Buffer overflow, DoS |
| CWE-191 | Integer Underflow/Wraparound | High | `0 - 1 = UINT_MAX` in allocation | Buffer overflow |
| CWE-192 | Integer Coercion Error | Medium | Implicit sign/width conversion | Logic error |
| CWE-193 | Off-by-One Error | Medium | `<=` vs `<` in loop bound | Buffer overflow |
| CWE-194 | Unexpected Sign Extension | Medium | Char to int sign extension | Logic error |
| CWE-195 | Signed to Unsigned Conversion Error | Medium | Negative to large unsigned | Buffer overflow |
| CWE-196 | Unsigned to Signed Conversion Error | Medium | Large unsigned to negative signed | Logic error |
| CWE-197 | Numeric Truncation Error | Medium | 64-bit to 32-bit truncation | Logic error |
| CWE-243 | Creation of chroot Jail Without chdir | Low | chroot without chdir | Jail escape |
| CWE-244 | Improper Clearing of Heap Memory Before Release | Low | Sensitive data in freed memory | Info leak |
| CWE-415 | Double Free | Critical | free() called twice on same pointer | RCE, DoS |
| CWE-416 | Use After Free | Critical | Accessing freed memory | RCE, info leak |
| CWE-457 | Use of Uninitialized Variable | Medium | Reading variable before assignment | Info leak, undefined behavior |
| CWE-467 | Use of sizeof() on a Pointer Type | Medium | sizeof(ptr) instead of sizeof(*ptr) | Buffer overflow |
| CWE-468 | Incorrect Pointer Scaling | Medium | sizeof wrong type in pointer arithmetic | Buffer overflow |
| CWE-476 | NULL Pointer Dereference | Medium | Deref NULL pointer | DoS |
| CWE-562 | Return of Stack Variable Address | High | Returning address of stack variable | Use-after-free |
| CWE-587 | Assignment of a Fixed Address to a Pointer | Low | Hardcoded pointer addresses | Unpredictable behavior |
| CWE-590 | Free of Memory not on the Heap | High | free() on stack/static memory | Crash, potential RCE |
| CWE-680 | Integer Overflow to Buffer Overflow | Critical | Overflow in size calc → buffer overflow | RCE |
| CWE-690 | Unchecked Return Value to NULL Pointer Dereference | Medium | malloc failure not checked | DoS |
| CWE-761 | Free of Pointer not at Start of Buffer | Medium | free(ptr+offset) | Crash |
| CWE-762 | Mismatched Memory Management Routines | Medium | new[] + free() or malloc() + delete | Crash |
| CWE-763 | Release of Invalid Pointer | Medium | free() on non-heap pointer | Crash |
| CWE-787 | Out-of-bounds Write | Critical | Writing past buffer boundary | RCE, corruption |
| CWE-788 | Access of Memory Location After End of Buffer | Critical | Read past buffer bound | Info leak |
| CWE-805 | Buffer Access with Incorrect Length Value | High | Wrong length passed to buffer op | Overflow |
| CWE-806 | Buffer Access Using Size of Source Buffer | High | Using sizeof(src) for copy size | Overflow |
| CWE-822 | Untrusted Pointer Dereference | Critical | User-controlled pointer | Arbitrary R/W |
| CWE-823 | Use of Out-of-Range Pointer Offset | High | User-controlled index into array | Arbitrary R/W |
| CWE-824 | Access of Uninitialized Pointer | High | Uninitialized pointer deref | Arbitrary R/W |
| CWE-825 | Expired Pointer Dereference | High | Deref of freed/dangling pointer | Use-after-free |

---

## CWE-2: Cross-Site Scripting (agent: web-api-agent) — ~60 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-79 | Cross-Site Scripting (XSS) | High | `<script>alert(1)</script>`, event handlers, javascript: URLs | Session hijack, phishing, keylogging |
| CWE-80 | Basic XSS (no encoding) | High | Raw HTML injection without sanitization | Cookie theft |
| CWE-81 | XSS via Error Message | Medium | Error pages reflecting user input as HTML | Phishing via error page |
| CWE-82 | XSS via HTTP Header | Medium | User-controlled headers reflected without sanitization | Cookie theft |
| CWE-83 | XSS via Script in Attributes | High | `onmouseover=`, `onerror=`, `onload=` in HTML attributes | Script exec |
| CWE-84 | XSS via URI Scheme | Medium | `javascript:` URI in href/src attributes | Script exec on click |
| CWE-85 | Doubled Character XSS Manipulation | Low | Double-encoding bypass (``&amp;lt;`` → `<`) | Filter bypass |
| CWE-86 | XSS via Invalid Characters in Identifiers | Low | NULL byte injection in tag names | Filter bypass |
| CWE-87 | XSS via Alternate XSS Syntax | Medium | Non-standard script syntax (VBScript, SVG onload) | Filter bypass |
| CWE-88 | XSS via HTML Entity Expansion | Low | Entity expansion creating HTML tags | Filter bypass |
| CWE-89 | DOM-Based XSS | High | `document.write(location.hash)`, `innerHTML = user_input` | Client-side XSS |
| CWE-90 | LDAP Injection | High | `*)(uid=*))(|(uid=*` in LDAP queries | Auth bypass, data exfil |
| CWE-91 | Blind XPath Injection | High | Boolean-based XPath query injection | XML data exfil |
| CWE-643 | XPath Injection | High | Unvalidated XPath query parameters | XML structure disclosure |
| CWE-652 | XQuery Injection | High | XML database query injection | Data exfil |
| CWE-917 | Expression Language Injection | Critical | `${7*7}` in JSP EL, Spring Expression Language | RCE |

### DOM-Based XSS Variants
| CWE | Name | Severity | Detection Pattern |
|-----|------|----------|-------------------|
| CWE-79 | DOM XSS in document.write | High | `document.write(user_input)` |
| CWE-79 | DOM XSS in innerHTML | High | `element.innerHTML = location.hash` |
| CWE-79 | DOM XSS in eval | Critical | `eval(location.hash.slice(1))` |
| CWE-79 | DOM XSS in setTimeout/setInterval | High | `setTimeout(user_input, 1000)` |
| CWE-79 | DOM XSS in javascript: URL | Medium | `location.href = 'javascript:' + user_input` |
| CWE-79 | DOM XSS in jQuery html() | High | `$('#div').html(user_input)` |
| CWE-79 | DOM XSS in React dangerouslySetInnerHTML | High | `dangerouslySetInnerHTML={{__html: user_input}}` |
| CWE-79 | DOM XSS in Angular bypassSecurityTrustHtml | Medium | `bypassSecurityTrustHtml(user_input)` |
| CWE-79 | DOM XSS in postMessage handler | High | `window.addEventListener('message', ...)` without origin check |
| CWE-79 | DOM XSS in Service Worker | Medium | Cached response manipulation |
| CWE-79 | DOM XSS in WebSocket message handler | High | `ws.onmessage = e => innerHTML = e.data` |
| CWE-79 | mXSS (Mutation XSS) | High | `innerHTML` → browser mutates → XSS after DOM change |
| CWE-79 | Blind XSS | High | XSS in admin panel/log viewer triggered later |
| CWE-79 | Self-XSS | Low | Requires victim to paste code themselves |
| CWE-79 | Stored XSS via File Upload (SVG/HTML) | High | SVG with `<script>` or `onload` uploaded |
| CWE-79 | Stored XSS via Markdown | Medium | HTML allowed in markdown rendering |
| CWE-79 | Universal XSS (UXSS) | Critical | Browser-level XSS bypassing same-origin |

### XSS Filter Bypass Techniques (CWE-79 variants)
- Null byte injection: `<scr%00ipt>`
- HTML entity encoding: `&lt;script&gt;`
- JS Unicode escapes: `\u003cscript\u003e`
- SVG namespace: `<svg><script>alert(1)</script></svg>`
- Case variation: `<ScRiPt>`
- Double encoding: `%253Cscript%253E`
- UTF-7 XSS: `+ADw-script+AD4-`
- CSS injection → XSS: `background: url("javascript:alert(1)")`
- Polyglot payloads: `javascript:/*-->*/</script><svg onload=alert(1)>`

---

## CWE-3: SSRF & URL Injection (agent: web-api-agent) — ~40 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-918 | Server-Side Request Forgery (SSRF) | Critical | URL parameter reaches HTTP client → internal requests | Cloud metadata access, internal port scan, RCE via internal services |
| CWE-919 | Weaknesses in Mobile Applications | Medium | Mobile SSRF via deeplink URL schemes | Internal network access |
| CWE-441 | Unintended Proxy/Intermediary | High | Open proxy allowing arbitrary destinations | Internal network access |
| CWE-610 | Externally-Controlled Reference to a Resource in Another Sphere | High | Cross-domain resource reference | Privilege bypass |
| CWE-611 | XXE → SSRF | Critical | `<!ENTITY xxe SYSTEM "http://169.254.169.254/">` | Cloud metadata exfil |
| CWE-641 | Improper Restriction of Names for Files and Other Resources | High | URL/file path manipulation | File read, SSRF |
| CWE-642 | External Control of Critical State Data | High | URL as state → SSRF | Internal access |
| CWE-646 | Reliance on File Name or Extension of Externally-Supplied File | Medium | Extension-based routing | SSRF via file:// |
| CWE-668 | Exposure of Resource to Wrong Sphere | High | Resource accessible from wrong security context | Information leak |
| CWE-706 | Use of Incorrectly-Resolved Name or Reference | High | Name resolution manipulation | DNS rebinding SSRF |
| CWE-918 | SSRF via gopher:// protocol | Critical | `gopher://internal:6379/_*1%0d%0a$8%0d%0aflushall` | Redis/SMTP exploitation |
| CWE-918 | SSRF via file:// protocol | High | `file:///etc/passwd` | File read |
| CWE-918 | SSRF via dict:// protocol | Medium | `dict://internal:11211/stats` | Memcached info |
| CWE-918 | SSRF via DNS rebinding | High | TTL=0 DNS → rebind to internal IP | Internal access |
| CWE-918 | SSRF via IP obfuscation | Medium | Decimal IP (`http://2130706433/` = 127.0.0.1) | Filter bypass |
| CWE-918 | SSRF via IPv6 | Medium | `http://[::1]/` to bypass IPv4 filters | Filter bypass |
| CWE-918 | SSRF via URL parser confusion | High | `http://expected@evil.com/` | Credential redirect |
| CWE-918 | SSRF via redirect | High | Open redirect → internal service | Filter bypass |
| CWE-918 | Blind SSRF | Medium | SSRF with no response (only side effects) | Internal scan |
| CWE-918 | Semi-blind SSRF | High | SSRF with partial response (timing, error messages) | Internal recon |
| CWE-918 | SSRF in PDF generators | High | HTML→PDF with iframe/embed to internal | Internal access |
| CWE-918 | SSRF in image processors | High | Image URL → fetch + process → internal access | Internal access |
| CWE-918 | SSRF in webhooks | Critical | Webhook URL → outbound request to internal | Internal access |
| CWE-918 | SSRF in file import (CSV, XML, DOCX) | High | Import triggers fetch to internal | Internal access |
| CWE-918 | SSRF in OAuth/OIDC callbacks | High | redirect_uri → internal SSRF | Token theft |

---

## CWE-4: Authentication & Session (agent: access-control-agent) — ~90 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-287 | Improper Authentication | Critical | Missing auth on sensitive endpoints | Full unauthorized access |
| CWE-288 | Authentication Bypass Using Alternate Path | Critical | `/admin/../user` path tricks | Auth bypass |
| CWE-289 | Authentication Bypass by Alternate Name | High | DNS rebinding, Host header manipulation | Auth bypass |
| CWE-290 | Authentication Bypass by Spoofing | Critical | IP spoofing, Referer spoofing | Auth bypass |
| CWE-291 | Reliance on IP Address for Authentication | Low | Trusting X-Forwarded-For without validation | Auth bypass |
| CWE-292 | Reliance on Reverse DNS for Authentication | Low | rDNS lookup for trust decisions | Auth bypass |
| CWE-293 | Reliance on DNS Lookups in a Security Decision | Low | DNS-based access control | Auth bypass |
| CWE-294 | Authentication Bypass by Capture-Replay | Critical | Session token reused, nonce replay | Session hijack |
| CWE-295 | Improper Certificate Validation | High | No SSL pinning, accepting any cert | MITM |
| CWE-296 | Improper Following of a Chain of Trust | High | Improper cert chain validation | MITM |
| CWE-297 | Improper Validation of Certificate with Host Mismatch | Medium | cert CN not matching hostname | MITM |
| CWE-298 | Improper Validation of Certificate Expiration | Low | Accepting expired certs | MITM |
| CWE-299 | Improper Check for Certificate Revocation | Medium | No CRL/OCSP checking | MITM with revoked cert |
| CWE-300 | Channel Accessible by Non-Endpoint (MITM) | High | Missing TLS entirely | Full traffic interception |
| CWE-301 | Reflection Attack on Authentication Protocol | High | Challenge-response reflection | Auth bypass |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data | High | Modifiable client data in auth decision | Auth bypass |
| CWE-303 | Incorrect Implementation of Authentication Algorithm | High | Custom broken crypto in auth | Auth bypass |
| CWE-304 | Missing Critical Step in Authentication | Critical | Auth flow missing verification step | Auth bypass |
| CWE-305 | Authentication Bypass by Primary Weakness | Critical | Weak password policy, no MFA | Credential brute force |
| CWE-306 | Missing Authentication for Critical Function | Critical | No auth on admin/reset/delete endpoints | Full compromise |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | High | No rate limit on login → brute force | Credential compromise |
| CWE-308 | Use of Single-factor Authentication | Medium | Password-only without MFA | Credential theft = ATO |
| CWE-309 | Use of Password System for Primary Authentication | Low | No supplemental factors | Credential risk |
| CWE-345 | Insufficient Verification of Data Authenticity | High | No signature/HMAC on auth tokens | Token forgery |
| CWE-346 | Origin Validation Error | High | Missing Origin/Referer check on CORS/state changes | CSRF, CORS attack |
| CWE-347 | Improper Verification of Cryptographic Signature | High | Missing or broken JWT signature verification | Token forgery |
| CWE-348 | Use of Less Trusted Source | Medium | Trusting client-supplied role/admin flag | Privilege escalation |
| CWE-349 | Acceptance of Extraneous Untrusted Data With Trusted Data | Medium | Mixing user + trusted data without separation | Data poisoning |
| CWE-350 | Reliance on Reverse DNS for a Security Decision | Low | rDNS for access control | Auth bypass |
| CWE-352 | Cross-Site Request Forgery (CSRF) | High | Missing CSRF token on state-changing requests | Forced actions on victim |
| CWE-353 | Missing Support for Integrity Check | Medium | No HMAC/digital signature on critical data | Data tampering |
| CWE-354 | Improper Validation of Integrity Check Value | High | Broken HMAC verification | Data forgery |
| CWE-355 | User Interface Security Issues | Low | UI misdirection for security | Clickjacking |
| CWE-356 | Product UI does not Warn User of Unsafe Actions | Low | No confirmation on dangerous action | Accidental action |
| CWE-357 | Insufficient UI Warning of Dangerous Operations | Low | Weak confirmation dialogs | Accidental action |
| CWE-358 | Improperly Implemented Security Check for Standard | Medium | Security check can be bypassed | Auth bypass |
| CWE-359 | Exposure of Private Personal Information to Unauthorized Actor | Critical | PII exposed without auth | Privacy violation |
| CWE-360 | Trust of System Event Data | Medium | Event spoofing | Log forgery |
| CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization (Race) | High | TOCTOU on auth check | Auth bypass via race |
| CWE-363 | Race Condition Enabling Link Following | Medium | Symlink race in auth | Auth bypass |
| CWE-364 | Signal Handler Race Condition | Medium | Signal between check and use | Auth bypass |
| CWE-365 | Race Condition in Switch | Low | Context switch race | Auth bypass |
| CWE-366 | Race Condition within a Thread | Medium | Thread race in auth check | Auth bypass |
| CWE-367 | Time-of-Check Time-of-Use (TOCTOU) | High | Auth check → gap → action | Auth bypass |
| CWE-368 | Context Switching Race Condition | Low | Context switch window | Auth bypass |
| CWE-384 | Session Fixation | High | Session ID set before login, not rotated after | Session hijack |
| CWE-488 | Exposure of Data Element to Wrong Session | Critical | Session data leaking between users | Cross-account data access |
| CWE-521 | Weak Password Requirements | Medium | No complexity/length requirements | Credential brute force |
| CWE-522 | Insufficiently Protected Credentials | Critical | Plaintext passwords, weak hashing (MD5/SHA1), hardcoded creds | Credential theft |
| CWE-523 | Unprotected Transport of Credentials | Critical | Login over HTTP (no TLS) | Credential sniffing |
| CWE-525 | Use of Web Browser Cache Containing Sensitive Info | Medium | Sensitive pages cached by browser | Local info disclosure |
| CWE-539 | Use of Persistent Cookies Containing Sensitive Info | Medium | Sensitive data in long-lived cookie | Info theft |
| CWE-549 | Missing Password Field Masking | Low | Plaintext password display | Shoulder surfing |
| CWE-565 | Reliance on Cookies without Validation and Integrity Checking | High | Unsigned cookies for auth decision | Cookie manipulation |
| CWE-592 | Authentication Bypass: OpenSSL CTX Object Modified | High | SSL context tampering after auth | Auth bypass |
| CWE-593 | Authentication Bypass: Modified OTG Authentication Data | High | OTP bypass via race/timing | Auth bypass |
| CWE-603 | Use of Client-Side Authentication | Critical | Auth logic in JavaScript on client | Auth bypass |
| CWE-613 | Insufficient Session Expiration | Medium | Session valid forever, no absolute timeout | Session reuse |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | Medium | Cookie sent over HTTP | Cookie theft via MITM |
| CWE-620 | Unverified Password Change | High | Password change without current password | ATO |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password | Critical | Guessable security questions, token not expiring | ATO via reset |
| CWE-645 | Overly Restrictive Account Lockout Mechanism | Medium | Lockout → DoS on all accounts | Account DoS |
| CWE-647 | Use of Non-Canonical URL Paths for Authorization Decisions | High | Auth decision on non-normalized path | Auth bypass |
| CWE-653 | Improper Isolation of Shared Resources in Network Virtualization | High | Cross-tenant access in shared infra | Tenant isolation bypass |
| CWE-654 | Reliance on a Single Factor in a Security Decision | Medium | Single auth factor for sensitive actions | Credential risk |
| CWE-655 | Insufficient Psychological Acceptability | Low | UX that encourages security bypass | Security workaround |
| CWE-656 | Reliance on Security Through Obscurity | Low | Hidden URL as "auth" | Auth bypass |
| CWE-798 | Use of Hard-coded Credentials | Critical | `admin:admin`, hardcoded API keys, default passwords | Full compromise |
| CWE-804 | Guessable CAPTCHA | Medium | Weak CAPTCHA implementation | Automated attack |
| CWE-836 | Use of Password Hash Instead of Password for Authentication | High | Pass-the-hash vulnerability | Auth bypass |
| CWE-840 | Business Logic Errors | High | Conditional auth bypass via unexpected flow | Auth bypass |
| CWE-841 | Improper Enforcement of Behavioral Workflow | High | Skipping steps in auth workflow | Auth bypass |
| CWE-862 | Missing Authorization | Critical | No authz check after authentication | IDOR, privilege escalation |
| CWE-863 | Incorrect Authorization | Critical | Wrong role check (OR instead of AND) | Privilege escalation |
| CWE-926 | Improper Export of Android Application Components | Medium | Exported activities without auth | Auth bypass |
| CWE-939 | Improper Authorization in Handler for Custom URL Scheme | High | Custom URL scheme without auth | Auth bypass |
| CWE-940 | Improper Verification of Source of a Communication Channel | High | No origin verification on IPC | Auth bypass |
| CWE-1275 | Cookie with Broad Domain Scope | Medium | Cookie scope too broad | Cross-subdomain attack |

### JWT-Specific Auth Weaknesses
| CWE | Name | Severity | Detection Pattern |
|-----|------|----------|-------------------|
| CWE-347 | JWT alg:none attack | Critical | `{"alg":"none"}` → no signature verification |
| CWE-347 | JWT algorithm confusion (RS256→HS256) | Critical | Sign with public key as HMAC secret |
| CWE-347 | JWT kid injection | Critical | `kid: "../../../../../etc/passwd"` → file read → key material |
| CWE-347 | JWT jku header injection | Critical | `jku: "https://evil.com/jwks.json"` → attacker's key |
| CWE-347 | JWT x5u header injection | Critical | x5u pointing to attacker's certificate |
| CWE-347 | JWT weak HMAC secret | High | Brute-forceable HMAC secret |
| CWE-347 | JWT missing exp claim | Medium | Token valid forever |
| CWE-347 | JWT iat not validated | Low | Replay of old tokens |

### OAuth 2.0 / OIDC Weaknesses
| CWE | Name | Severity | Detection Pattern |
|-----|------|----------|-------------------|
| CWE-601 | OAuth redirect_uri validation bypass | Critical | Open redirect in redirect_uri → code theft |
| CWE-601 | OAuth CSRF (missing state param) | High | No state → CSRF on authorization URL → account linking |
| CWE-601 | OAuth implicit flow token leak | High | Access token in URL fragment/referer |
| CWE-601 | OAuth PKCE bypass | High | Missing PKCE on public clients |
| CWE-601 | OAuth scope upgrade | Critical | `scope=read` → `scope=read+write+admin` |
| CWE-601 | OAuth client_secret in mobile app | Medium | Hardcoded secret extractable from APK/IPA |
| CWE-601 | OAuth mix-up attack | High | Multiple IdPs → confused authorization server |
| CWE-601 | OAuth 307 redirect body forwarding | High | POST body forwarded on 307 redirect |

---

## CWE-5: Authorization & Access Control (agent: access-control-agent) — ~80 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-639 | Insecure Direct Object Reference (IDOR) - User | Critical | Change `/user/123` → `/user/456`, see other's data | Cross-user data access |
| CWE-639 | IDOR - Horizontal | Critical | Same-level user accessing peer data | PII exposure |
| CWE-639 | IDOR - Vertical | Critical | User accessing admin resource by ID | Privilege escalation |
| CWE-639 | IDOR - UUID/GUID based | Medium | UUIDs are not auth; sequential or enumerable | Cross-user access |
| CWE-639 | IDOR - Hashed IDs | Medium | Hash(id) still enumerable if predictable | Cross-user access |
| CWE-639 | IDOR - JWT subject mismatch | High | JWT sub != resource owner | Cross-user access |
| CWE-862 | Missing Authorization | Critical | No authz check on API endpoint | Unauthorized access |
| CWE-863 | Incorrect Authorization | Critical | Wrong authz logic (OR of roles) | Privilege escalation |
| CWE-866 | Missing Authorization for Function | High | No role check on admin function | Unauthorized admin |
| CWE-250 | Execution with Unnecessary Privileges | Medium | Service running as root unnecessarily | Privilege abuse |
| CWE-264 | Permissions, Privileges, and Access Controls (meta) | — | Parent category for all authz issues | — |
| CWE-266 | Incorrect Privilege Assignment | Critical | User assigned wrong role/permissions | Privilege escalation |
| CWE-267 | Privilege Defined With Unsafe Actions | Critical | High-privilege role with no guardrails | Privilege abuse |
| CWE-268 | Privilege Chaining | High | Combining two medium privs → critical priv | Privilege escalation |
| CWE-269 | Improper Privilege Management | Critical | Privilege not revoked, not validated | Privilege escalation |
| CWE-270 | Privilege Context Switching Error | Medium | Wrong user context after switch | Cross-user access |
| CWE-271 | Privilege Dropping / Lowering Errors | Medium | Privilege not dropped after use | Privilege abuse |
| CWE-272 | Least Privilege Violation | Medium | Process runs with more privs than needed | Privilege abuse |
| CWE-273 | Improper Check for Dropped Privileges | Medium | Failed privilege drop not detected | Privilege abuse |
| CWE-274 | Improper Handling of Insufficient Privileges | Medium | Error path leaks elevated access | Privilege escalation |
| CWE-275 | Permission Issues | — | Parent category | — |
| CWE-276 | Incorrect Default Permissions | High | File/dir world-writable, 777 by default | File tampering |
| CWE-277 | Insecure Inherited Permissions | Medium | Child inherits parent's excessive permissions | Privilege escalation |
| CWE-278 | Insecure Preserved Inherited Permissions | Medium | Permissions persist through copy/move | Data exposure |
| CWE-279 | Insecure Execution-Assigned Permissions | High | Runtime permissions too broad | Privilege abuse |
| CWE-280 | Improper Handling of Insufficient Permissions or Privileges | Medium | Error path bypass | Authz bypass |
| CWE-281 | Improper Preservation of Permissions | Medium | Permissions lost/misapplied on save/restore | Authz bypass |
| CWE-282 | Improper Ownership Management | High | Object owner can be changed without check | Takeover |
| CWE-283 | Unverified Ownership | High | No check that requestor owns the resource | Cross-user access |
| CWE-284 | Improper Access Control | Critical | Catch-all for missing/weak access control | Unauthorized access |
| CWE-285 | Improper Authorization | Critical | Authz check missing or incomplete | Unauthorized access |
| CWE-286 | Incorrect User Management | High | User role management without proper validation | Privilege escalation |
| CWE-441 | Unintended Proxy | High | Acting as proxy without checks | Auth bypass |
| CWE-472 | External Control of Assumed-Immutable Web Parameter | High | Modifying "immutable" values (ids, roles, prices) | Privilege escalation |
| CWE-488 | Data Leak Between Sessions | Critical | Session mix-up → wrong user's data | Cross-account access |
| CWE-501 | Trust Boundary Violation | Critical | Trusted and untrusted data mixed | Privilege escalation |
| CWE-552 | Files or Directories Accessible to External Parties | Critical | `/admin`, `/backup`, `/.git`, `/.env` accessible | Source/config disclosure |
| CWE-556 | ASP.NET Misconfiguration: Use of Identity Impersonation | Medium | Excessive impersonation rights | Privilege escalation |
| CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key | High | User controls which row via PK → IDOR | Cross-user data |
| CWE-592 | Authentication Bypass: OpenSSL CTX Modified | High | SSL context modified post-auth | Auth bypass |
| CWE-638 | Not Using Complete Mediation | High | Access control enforced only at some layers | Auth bypass |
| CWE-639 | Authorization Bypass Through User-Controlled Key | Critical | Entity key from user input without ownership check | IDOR |
| CWE-642 | External Control of Critical State Data | Critical | Price, role, permissions from client | Business logic abuse |
| CWE-648 | Incorrect Use of Privileged APIs | High | Using sudo/admin API without validation | Privilege escalation |
| CWE-649 | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | Medium | Trusting client-encrypted values | Data tampering |
| CWE-650 | Trusting HTTP Permission Methods on the Server Side | Medium | Only checking HTTP method for authz | Auth bypass via method switch |
| CWE-668 | Exposure of Resource to Wrong Sphere | Critical | Data exposed to wrong security context | Information leak |
| CWE-669 | Incorrect Resource Transfer Between Spheres | High | Data moves across trust boundary unchecked | Data leak |
| CWE-708 | Incorrect Ownership Assignment | High | Resource assigned to wrong owner | Takeover |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | Critical | Sensitive file with wrong permissions | Data exposure |
| CWE-782 | Exposed IOCTL with Insufficient Access Control | Medium | Kernel-level access without checks | Privilege escalation |
| CWE-842 | Placement of User into Incorrect Group | Medium | Wrong group assignment | Authz bypass |
| CWE-921 | Storage of Sensitive Data in a Mechanism without Access Control | Critical | Sensitive data in unprotected storage | Data exposure |
| CWE-922 | Insecure Storage of Sensitive Information | Critical | Credentials in plaintext, weak encryption at rest | Data theft |
| CWE-923 | Improper Restriction of Communication Channel Access | High | Unauthorized access to IPC, sockets | Privilege escalation |
| CWE-927 | Use of Implicit Intent for Sensitive Communication (Android) | Medium | Implicit intents visible to all apps | Data leak |
| CWE-939 | Improper Authorization in Handler for Custom URL Scheme | High | Custom URL scheme without permission check | Auth bypass |
| CWE-1220 | Insufficient Granularity of Access Control | Medium | Too-coarse authz (all-or-nothing) | Over-privilege |
| CWE-1230 | Exposure of Sensitive Information Through Metadata | High | Auth tokens, keys in metadata | Credential leak |
| CWE-1244 | Internal Asset Exposed to Unsafe Debug Access | Medium | Debug endpoints without auth | Info disclosure |
| CWE-1250 | Improper Preservation of Consistency Between Independent Representations of Shared State | Medium | Auth state inconsistency | Auth bypass |
| CWE-1270 | Generation of Incorrect Security Tokens | High | Token generation logic broken | Auth bypass |
| CWE-1283 | Black Box of Authorization Data | Medium | Opaque authz data that should be validated | Authz bypass |
| CWE-1290 | Inclusion of Sensitive Information in an Archive | High | Auth data in log archives/backups | Credential leak |
| CWE-1293 | Missing Source Validation of Security Tokens | High | Token accepted from any source | Token forgery |
| CWE-1313 | Hardware Allows Activation of Test or Debug Logic at Runtime | Low | JTAG debug interface enabled | Physical access bypass |
| CWE-1320 | Improper Protection for Outbound Error Messages and Alert Signals | Low | Auth status revealed in error messages | User enumeration |

---

## CWE-6: Cryptographic Weaknesses (agent: crypto-math-agent) — ~70 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-310 | Cryptographic Issues (meta) | — | Parent category | — |
| CWE-311 | Missing Encryption of Sensitive Data | Critical | PII/credentials stored plaintext | Data theft |
| CWE-312 | Cleartext Storage of Sensitive Information | Critical | DB columns with plaintext passwords | Data breach |
| CWE-313 | Cleartext Storage in File or on Disk | Critical | Config files with plaintext secrets | Credential theft |
| CWE-314 | Cleartext Storage in the Registry | High | Windows registry with plaintext secrets | Credential theft |
| CWE-315 | Cleartext Storage of Sensitive Information in a Cookie | High | Sensitive data in unencrypted cookie | Session hijack |
| CWE-316 | Cleartext Storage of Sensitive Information in Memory | Medium | Secrets in process memory dumps | Memory forensics |
| CWE-317 | Cleartext Storage in GUI | Low | Password shown in UI field | Shoulder surfing |
| CWE-318 | Cleartext Storage in Executable | Medium | Hardcoded secrets in binary | Reverse engineering |
| CWE-319 | Cleartext Transmission of Sensitive Information | Critical | HTTP for login, API keys in URL | Network sniffing |
| CWE-320 | Key Management Errors | — | Parent category | — |
| CWE-321 | Use of Hard-coded Cryptographic Key | Critical | Encryption key in source code | Full decryption |
| CWE-322 | Key Exchange without Entity Authentication | Critical | Diffie-Hellman without auth → MITM | Key compromise |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption | Critical | Nonce reuse in stream ciphers, AES-GCM | Ciphertext forgery |
| CWE-324 | Use of a Key Past its Expiration Date | Low | Expired signing key still trusted | Signature bypass |
| CWE-325 | Missing Cryptographic Step | Critical | Missing MAC verification, missing padding check | Data forgery |
| CWE-326 | Inadequate Encryption Strength | Critical | 512-bit RSA, DES, RC4, MD5, SHA1 | Brute force feasible |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Critical | MD5, SHA1, RC4, DES, ECB mode | Practical attacks exist |
| CWE-328 | Use of Weak Hash | Critical | CRC32, Adler-32 for integrity | Hash collision |
| CWE-329 | Generation of Predictable IV with CBC Mode | High | Fixed IV, sequential IV in CBC | Ciphertext analysis |
| CWE-330 | Use of Insufficiently Random Values | Critical | `rand()`, `Math.random()` for crypto, predictable seed | Token/IV/key prediction |
| CWE-331 | Insufficient Entropy | Critical | Low-entropy PRNG seed | Key recovery |
| CWE-332 | Insufficient Entropy in PRNG | Critical | Predictable PRNG output | Token prediction |
| CWE-333 | Improper Handling of Insufficient Entropy in TRNG | High | TRNG failure not handled | Weak keys |
| CWE-334 | Small Space of Random Values | High | Token space too small → brute force | Token forgery |
| CWE-335 | Incorrect Usage of Seeds in PRNG | Critical | Seed reuse, fixed seed, timestamp as seed | Seed recovery |
| CWE-336 | Same Seed in PRNG | Critical | Same seed → same output | Prediction |
| CWE-337 | Predictable Seed in PRNG | Critical | Timestamp/PID as seed | Seed prediction |
| CWE-338 | Use of Cryptographically Weak PRNG | Critical | LCG, Mersenne Twister for security tokens | Token prediction |
| CWE-339 | Small Seed Space in PRNG | Medium | 32-bit seed brute-forceable | Seed recovery |
| CWE-340 | Generation of Predictable Numbers or Identifiers | High | Sequential IDs, timestamp-based tokens | Token prediction |
| CWE-341 | Predictable from Observable State | Medium | Seed derivable from observable output | PRNG state recovery |
| CWE-342 | Predictable Exact Value from Previous Values | High | Token[n+1] predictable from token[n] | Token prediction |
| CWE-343 | Predictable Value Range from Previous Values | Medium | Narrowed range prediction | Range prediction |
| CWE-344 | Use of Invariant Value in Dynamically Changing Context | Medium | Constant value where random expected | Predictable output |
| CWE-347 | Improper Verification of Cryptographic Signature | Critical | Signature not verified, wrong algorithm | Signature bypass |
| CWE-348 | Use of Less Trusted Source | Medium | Trusting untrusted signature source | Signature bypass |
| CWE-349 | Acceptance of Extraneous Untrusted Data With Trusted Data | Medium | Extra data in signed blob | Signature bypass |
| CWE-351 | Insufficient Type Distinction | Medium | Same key for encrypt+sign | Key reuse attack |
| CWE-354 | Improper Validation of Integrity Check Value | High | CRC for security, weak checksum | Integrity bypass |
| CWE-356 | Product UI does not Warn User | Low | No warning on weak security | User mistake |
| CWE-522 | Insufficiently Protected Credentials | Critical | Weak hashing (no salt, single iteration) | Credential cracking |
| CWE-523 | Unprotected Transport of Credentials | Critical | No TLS for login/API keys | Credential sniffing |
| CWE-524 | Use of Cache Containing Sensitive Information | Medium | Encryption keys cached to disk | Key theft |
| CWE-525 | Use of Web Browser Cache With Sensitive Info | Medium | Encrypted data cached client-side | Local attack |
| CWE-526 | Exposure of Sensitive Information Through Environmental Variables | High | Keys in env vars → /proc/self/environ | Key leak |
| CWE-527 | Exposure of Version-Control Repository to Unauthorized Actor | Critical | .git exposed → source + keys | Full compromise |
| CWE-528 | Exposure of Core Dump File to Unauthorized Actor | Medium | Core dumps with key material | Key recovery |
| CWE-529 | Exposure of Access Control List Files | Medium | ACL files world-readable | Permission bypass |
| CWE-530 | Exposure of Backup File to Unauthorized Actor | High | .bak, .swp, ~ files with keys | Credential leak |
| CWE-531 | Exposure of Sensitive Information Through Test Code | High | Test files with real credentials | Credential leak |
| CWE-532 | Insertion of Sensitive Information into Log File | High | Passwords/tokens in logs | Log-based credential leak |
| CWE-533 | Deprecated Information in Log | Medium | Logs expose sensitive deprecated info | Information leak |
| CWE-534 | Information Leak Through Debug Sources | High | Debug output with secrets | Credential leak |
| CWE-535 | Information Leak Through Shell Error Message | Medium | Error messages reveal crypto state | Key inference |
| CWE-536 | Information Leak Through Servlet Runtime Error | Medium | Stack traces with crypto internals | Implementation leak |
| CWE-537 | Information Leak Through Java Runtime Error | Medium | Exception with crypto details | Implementation leak |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File/Dir | Critical | .git, .svn, .DS_Store, .env exposed | Full source/cred leak |
| CWE-540 | Information Leak Through Source Code | Critical | Source code exposed → all bugs visible | Full recon |
| CWE-541 | Information Leak Through Include Source Code | Critical | PHP include source disclosure | Source leak |
| CWE-542 | Information Leak Through Debug Symbols | Medium | Debug binaries with symbols | Reverse engineering |
| CWE-543 | Information Leak Through Debug Information | Medium | Debug mode in production | Source disclosure |
| CWE-544 | Missing Fallback in Security-Sensitive Code | Medium | No fallback when crypto fails → no encryption | Data exposure |
| CWE-545 | Use of Dynamic Class Loading with Untrusted Input | High | Class.forName(user_input) | RCE |
| CWE-546 | Suspicious Comment | Low | TODO/FIXME/HACK in security code | Undocumented weakness |
| CWE-547 | Use of Hard-coded, Security-Relevant Constants | High | Hardcoded salts, IVs, keys | Constant recovery |
| CWE-548 | Exposure of Information Through Directory Listing | Medium | Directory listing exposes .pem/.key files | Key exposure |
| CWE-549 | Missing Password Field Masking | Low | Passwords shown in UI | Shoulder surfing |
| CWE-554 | ASP.NET Misconfig: Not Using Input Validation Framework | Medium | Missing validation | Various injection |
| CWE-555 | J2EE Misconfig: Plaintext Password in Config File | Critical | `web.xml` or `server.xml` with plaintext creds | Credential theft |
| CWE-556 | ASP.NET Misconfig: Use of Identity Impersonation | Medium | Excessive identity impersonation | Privilege abuse |
| CWE-591 | Sensitive Data Storage in Improperly Locked Memory | Medium | Crypto keys in swappable memory | Memory dump → keys |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | Medium | Auth cookie not marked Secure | Cookie theft |
| CWE-615 | Information Leak Through Comments | Low | API keys, passwords in code comments | Credential leak |
| CWE-759 | Use of a One-Way Hash without a Salt | High | Unsalted MD5/SHA1 for passwords | Rainbow table attack |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | Medium | Username/email as salt | Targeted rainbow table |
| CWE-780 | Use of RSA without OAEP | Medium | PKCS#1 v1.5 padding → Bleichenbacher | Ciphertext decryption |
| CWE-818 | Insufficient Transport Layer Protection | High | Weak TLS version/ciphers | MITM |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | High | Single SHA-256 iteration for passwords | GPU brute force |
| CWE-1240 | Use of a Cryptographic Primitive with a Risky Implementation | High | Custom/broken implementation of standard | Implementation attack |

---

## CWE-7: Business Logic (agent: business-logic-agent) — ~50 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-840 | Business Logic Errors | Varies | Any path that violates assumed workflow | Financial loss, data corruption |
| CWE-841 | Improper Enforcement of Behavioral Workflow | High | Skip step 2, go directly to step 4 | Workflow bypass |
| CWE-837 | Improper Enforcement of a Single, Unique Action | High | Use coupon code twice, vote twice | Financial loss, manipulation |
| CWE-838 | Inappropriate Encoding for Output Context | Medium | Wrong encoding → logic bypass | Filter bypass |
| CWE-839 | Numeric Range Comparison Without Minimum Check | High | Negative price, negative quantity, zero amount | Financial loss |
| CWE-841 | Race condition in business workflow | High | Two parallel requests both succeed | Double-spend |
| CWE-1284 | Improper Validation of Specified Quantity in Input | Critical | Quantity=-1, quantity=99999 | Price manipulation |
| CWE-1285 | Improper Validation of Specified Index, Position, or Offset in Input | High | Index=-1 → access last element | Data manipulation |
| CWE-1286 | Improper Validation of Syntactic Correctness of Input | Medium | Malformed but accepted input | Logic bypass |
| CWE-1287 | Improper Validation of Specified Type of Input | Medium | String where int expected | Type confusion |
| CWE-1288 | Improper Validation of Consistency Within Input | High | Inconsistent input fields accepted | Business rule bypass |
| CWE-1289 | Improper Validation of Unsafe Equivalence in Input | High | `admin` == `ADMIN` == `admın` (Unicode) | Auth bypass |
| CWE-1291 | Public Key Re-Use for Signing | Medium | Same key for signing and encryption | Key reuse attack |
| CWE-1292 | Assumed-Immutable Data is Modified | Critical | Price in hidden field can be modified | Price manipulation |
| CWE-472 | External Control of Assumed-Immutable Web Parameter | Critical | Modify hidden/readonly form fields | Price, role, permission change |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Critical | Max length, price floor enforced only in JS | Server-side bypass |
| CWE-784 | Reliance on Cookies without Validation for Business Logic | High | Cookie stores price/discount/quantity | Price manipulation |
| CWE-807 | Reliance on Untrusted Inputs in a Security Decision | Critical | Trusting user-supplied role/price/admin flag | Full compromise |
| CWE-830 | Inclusion of Web Functionality from an Untrusted Source | High | Third-party script with business logic access | Supply chain, data theft |
| CWE-831 | Signal Handler Function Associated with Incorrect Signal | Medium | Wrong signal handler → unexpected behavior | Logic error |
| CWE-832 | Unlock of a Resource That is Not Locked | Medium | Unlock without lock → race condition | Concurrency bug |
| CWE-833 | Deadlock | Medium | Two locks acquired in different order | DoS |
| CWE-834 | Excessive Iteration | Medium | Infinite loop on user input | DoS |
| CWE-835 | Loop with Unreachable Exit Condition (Infinite Loop) | Medium | No exit from loop | DoS |
| CWE-836 | Use of Password Hash Instead of Password | High | Pass-the-hash | Auth bypass |
| CWE-841 | Workflow bypass | High | Skip payment → get product | Financial loss |
| CWE-909 | Missing Initialization of Resource | Medium | Uninitialized state variable | Undefined behavior |
| CWE-910 | Use of Expired File Descriptor | Low | Stale fd used | Undefined behavior |
| CWE-911 | Improper Update of Reference Count | Medium | Refcount underflow → UAF | Memory corruption |
| CWE-912 | Hidden Functionality (Backdoor) | Critical | Undocumented admin endpoint, magic parameter | Full compromise |
| CWE-913 | Improperly Controlled Modification of Dynamically-Managed Code Resources | High | Dynamic code loading without check | Code exec |
| CWE-914 | Improper Control of Dynamically-Identified Variables | High | Variable variables with user input | Code exec |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | High | Mass assignment, `$obj->$key = $value` | Property injection |
| CWE-915 | Mass Assignment / Auto-Binding | Critical | `User.update(params)` without whitelist → role=admin | Privilege escalation |
| CWE-940 | Improper Verification of Source of Communication Channel | High | IPC without source check | Unauthorized command |
| CWE-941 | Incorrectly Specified Destination in a Communication Channel | High | Message routed to wrong recipient | Data leak |
| CWE-942 | Overly Permissive Cross-domain Whitelist | Medium | CORS * with credentials | Cross-origin data theft |

### Financial & Payment Logic (subset of CWE-840/841)
| Pattern | Detection | Impact |
|---------|-----------|--------|
| Negative price/quantity | `price=-100`, `quantity=-1` | Payment to attacker |
| Currency confusion | `amount=100&currency=USD` → change to `JPY` | Pay 100 JPY instead of 100 USD |
| Race condition on balance | Parallel withdrawal requests both succeed | Double-spend |
| Rounding abuse | Repeated micro-transactions exploiting rounding | Cumulative theft |
| Coupon stacking | Apply multiple coupons beyond limit | Excessive discount |
| Referral self-abuse | Self-referral for unlimited credits | Free credits |
| Time-of-check time-of-use on payment | Check balance → delay → spend → withdraw | Overdraft |
| Integer overflow in total | Order 2^31 items → overflow → $0 total | Free items |
| Subscription lifecycle bypass | Cancel → use → refund → keep access | Free service |

---

## CWE-8: Race Conditions (agent: race-condition-agent) — ~35 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-362 | Concurrent Execution with Improper Synchronization | High | No lock/mutex on shared resource | Race condition |
| CWE-363 | Race Condition Enabling Link Following | Medium | Symlink created between check and open | File manipulation |
| CWE-364 | Signal Handler Race Condition | Medium | Signal arrives during non-atomic operation | State corruption |
| CWE-365 | Race Condition in Switch | Low | Context switch during critical section | State corruption |
| CWE-366 | Race Condition within a Thread | Medium | Multiple threads on shared data without sync | Data corruption |
| CWE-367 | Time-of-Check Time-of-Use (TOCTOU) | High | Check state → state changes → use old assumption | Auth bypass, double-spend |
| CWE-368 | Context Switching Race Condition | Low | Context switch during security operation | State corruption |
| CWE-369 | Divide By Zero | Medium | Denominator can be zero during race | Crash, DoS |
| CWE-370 | Missing Check for Certificate Revocation after Initial Check | Low | CRL/OCSP checked then race | Auth bypass |
| CWE-371 | State Issues (meta) | — | Parent category | — |
| CWE-372 | Incomplete Internal State Distinction | Medium | Same state representation for different actual states | State confusion |
| CWE-373 | Race Condition in Web Application | High | Parallel HTTP requests creating race window | Double-submit, double-spend |
| CWE-374 | Passing Mutable Objects to an Untrusted Method | Medium | Object modified by callee during caller's use | State corruption |
| CWE-375 | Returning a Mutable Object to an Untrusted Caller | Medium | Caller modifies returned object | State corruption |
| CWE-376 | Temporary File Race Condition | Medium | Temp file created → attacker replaces before use | File manipulation |
| CWE-377 | Insecure Temporary File | Medium | Predictable temp file name → symlink attack | File manipulation |
| CWE-378 | Creation of Temporary File With Insecure Permissions | Medium | Temp file world-writable | File tampering |
| CWE-379 | Creation of Temporary File in Directory with Insecure Permissions | Medium | /tmp/ with sticky bit abuse | File tampering |
| CWE-380 | Time-of-Introduction Race (Deployment) | Low | Library replaced between build and deploy | Supply chain |
| CWE-381 | J2EE Misconfiguration: Race Condition in Error Handling | Low | Error during error handling | DoS |
| CWE-382 | J2EE Bad Practices: Use of System.exit() | Low | Process termination | DoS |
| CWE-383 | J2EE Bad Practices: Direct Use of Threads | Medium | Unmanaged threads in app server | Resource leak |
| CWE-384 | Session Fixation | High | Attacker sets victim's session ID | Session hijack |
| CWE-385 | Covert Timing Channel | Low | Timing side-channel | Info leak |
| CWE-386 | Symbolic Name not Mapping to Correct Object | Medium | Name resolution race | Wrong object |
| CWE-408 | Incorrect Behavior Order: Early Amplification | Medium | Amplified operation before validation | DoS |
| CWE-409 | Improper Handling of Highly Compressed Data | Medium | Zip bomb → resource exhaustion | DoS |
| CWE-410 | Insufficient Resource Pool | Medium | Connection pool exhaustion | DoS |
| CWE-411 | Resource Locking Problems | Medium | Lock not released, wrong lock order | Deadlock |
| CWE-412 | Unrestricted Externally Accessible Lock | Medium | Remote-accessible lock object | Remote deadlock |
| CWE-413 | Improper Resource Locking | Medium | Lock too broad or too narrow | Performance, race |
| CWE-414 | Missing Lock Check | Medium | Code assumes lock held when it's not | Race condition |
| CWE-543 | Use of Singleton Pattern Without Synchronization | Medium | Lazy init singleton in multi-threaded | Multiple instances |
| CWE-567 | Unsynchronized Access to Shared Data in Multithreaded Context | High | No synchronization on shared counter/map | Data corruption |
| CWE-609 | Double-Checked Locking | Medium | Broken double-checked locking pattern | Race condition |
| CWE-662 | Improper Synchronization | High | Wrong synchronization primitive or missing | Data corruption |
| CWE-663 | Use of a Non-Reentrant Function in Concurrent Context | Medium | Non-reentrant function in signal handler/signal-thread | State corruption |
| CWE-664 | Improper Control of a Resource Through its Lifetime | Medium | Resource lifecycle race | Use-after-free |
| CWE-665 | Improper Initialization | Medium | Object used before fully initialized | Race condition |
| CWE-666 | Operation on Resource in Wrong Phase of Lifetime | Medium | Resource used after close | Use-after-free |
| CWE-667 | Improper Locking | High | Wrong lock, missing unlock, deadlock | Race, DoS |
| CWE-674 | Uncontrolled Recursion | Medium | Recursion depth controllable by attacker | Stack overflow, DoS |
| CWE-675 | Multiple Operations on Resource in Single Operation Context | Medium | Atomicity violation | Partial update |
| CWE-820 | Missing Synchronization | High | Shared data accessed without sync primitive | Data corruption |
| CWE-821 | Incorrect Synchronization | High | Wrong sync mechanism for context | Race condition |
| CWE-1084 | Invocation of a Control Element Using Multiple Conflicting Conditions | Medium | Nested condition race | Logic error |
| CWE-1189 | Improper Isolation of Shared Resources on System-on-a-Chip | Low | Shared resource across security domains | Cross-domain leak |

### Web Race Condition Patterns
| Pattern | Detection | Impact |
|---------|-----------|--------|
| Single-packet attack | Send multiple requests in single TCP packet | Bypass rate limits |
| Last-byte sync | Hold request bodies, send last byte simultaneously | Simultaneous processing |
| Turbo Intruder race | Burp Turbo Intruder with `race=True` | Time-window exploitation |
| Discount code race | Apply code in two parallel checkouts | Double discount |
| Registration race | Register same username/email twice | Duplicate account |
| File upload race | Upload + request before virus scan/processing | Malicious file execution |
| Wallet race | Withdraw + spend simultaneously | Balance manipulation |
| OTP brute force via race | Multiple OTP attempts in parallel | Auth bypass |
| Rate limit race | Burst of requests arriving simultaneously | Rate limit bypass |

---

## CWE-9: Information Leakage (agent: recon-agent + credential-leak-agent) — ~60 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-200 | Exposure of Sensitive Information to Unauthorized Actor | Varies | Any data visible that shouldn't be | Information leak |
| CWE-201 | Insertion of Sensitive Information Into Sent Data | High | Referer header leaks session token | Session hijack |
| CWE-202 | Exposure of Sensitive Information Through Data Queries | High | Error message reveals DB structure | Recon |
| CWE-203 | Observable Discrepancy (Information Leak) | Medium | Different error for valid/invalid user | User enumeration |
| CWE-204 | Observable Response Discrepancy | Medium | Timing, content-length difference | User enumeration |
| CWE-205 | Observable Behavioral Discrepancy | Medium | Different behavior for different users | User enumeration |
| CWE-206 | Observable Internal Behavioral Discrepancy | Medium | Internal state reflected externally | State inference |
| CWE-207 | Observable Behavioral Discrepancy With Equivalent Products | Low | Version-specific behavior | Version fingerprint |
| CWE-208 | Observable Timing Discrepancy | Medium | Response time varies by input | Side-channel |
| CWE-209 | Generation of Error Message Containing Sensitive Information | High | Stack traces, SQL errors, path disclosure | Recon |
| CWE-210 | Self-Generated Error Message Containing Sensitive Information | Medium | Custom error with too much detail | Recon |
| CWE-211 | Externally-Generated Error Message Containing Sensitive Info | Low | Upstream error propagated to user | Recon |
| CWE-212 | Improper Removal of Sensitive Info Before Storage or Transfer | High | Sensitive data in cache/swap | Persistent leak |
| CWE-213 | Exposure of Sensitive Info Due to Incompatible Policies | Medium | Policy mismatch → leak | Data leak |
| CWE-214 | Invocation of Process Using Visible Sensitive Information | Medium | Password in ps output | Credential leak |
| CWE-215 | Insertion of Sensitive Information Into Debug Information | High | Debug mode in production reveals secrets | Credential leak |
| CWE-216 | Containment Errors (Container Errors) | Low | Container boundary issue | Information leak |
| CWE-217 | Failure to Protect Stored Data from Physical Attack | Low | Physical disk access | Data theft |
| CWE-218 | DEPRECATED | — | — | — |
| CWE-219 | Storage of File With Sensitive Data Under Web Root | Critical | .git, .env, .pem exposed via web | Full compromise |
| CWE-220 | Storage of File With Sensitive Data Under FTP Root | High | Sensitive data via FTP anonymous | Data leak |
| CWE-221 | Information Loss or Omission | Low | Data truncated → info loss | Data integrity |
| CWE-222 | Truncation of Security-Relevant Information | Low | Auth data truncated | Auth bypass |
| CWE-223 | Omission of Security-Relevant Information | Low | Missing security metadata | Auth bypass |
| CWE-224 | Obscured Security-Relevant Information by Alternate Name | Low | Security info hidden behind alias | Hidden risk |
| CWE-225 | DEPRECATED | — | — | — |
| CWE-226 | Sensitive Information Uncleared Before Release | High | Memory/page with secrets not cleared | Memory dump → keys |
| CWE-227 | 7PK - API Abuse | Medium | API used incorrectly | Various |
| CWE-228 | Improper Handling of Syntactically Invalid Structure | Medium | Parser confusion → bypass | Filter bypass |
| CWE-229 | Improper Handling of Values | Medium | Value not sanitized | Injection |
| CWE-230 | Improper Handling of Missing Values | Medium | Missing param default → bypass | Auth bypass |
| CWE-231 | Improper Handling of Extra Values | Medium | Extra param processed | Parameter injection |
| CWE-232 | Improper Handling of Undefined Values | Medium | Undefined treated as privileged | Auth bypass |
| CWE-233 | Improper Handling of Parameters | Medium | Parameter not validated | Injection |
| CWE-234 | Failure to Handle Missing Parameter | Medium | Missing required param → error path | Info leak |
| CWE-235 | Improper Handling of Extra Parameters | Medium | Extra params → unexpected behavior | Logic bypass |
| CWE-236 | Improper Handling of Undefined Parameters | Medium | Undefined param → default value | Logic bypass |
| CWE-237 | Improper Handling of Structural Elements | Medium | Malformed structure accepted | Parser bypass |
| CWE-238 | Improper Handling of Incomplete Structural Elements | Medium | Truncated input → parser confusion | Filter bypass |
| CWE-239 | Failure to Handle Incomplete Element | Medium | Incomplete data → partial processing | Logic error |
| CWE-240 | Improper Handling of Inconsistent Structural Elements | Medium | Conflicting fields → ambiguous state | Logic bypass |
| CWE-241 | Improper Handling of Unexpected Data Type | Medium | Array where string expected → crash | DoS, type juggling |
| CWE-242 | Use of Inherently Dangerous Function | Critical | `gets()`, `strcpy()`, `system()`, `eval()` | RCE, overflow |
| CWE-243 | Creation of chroot Jail Without Changing Working Directory | Low | chroot without chdir → escape | Jail escape |
| CWE-244 | Improper Clearing of Heap Memory Before Release | Low | Sensitive data in freed heap | Info leak |
| CWE-497 | Exposure of Sensitive System Information to Unauthorized Control Sphere | High | /proc, /sys, JMX, Actuator exposed | Full system recon |
| CWE-498 | Cloneable Class Containing Sensitive Information | Low | clone() copies sensitive data | Info leak |
| CWE-499 | Serializable Class Containing Sensitive Data | Medium | Serialization exposes sensitive fields | Data leak |
| CWE-524 | Information Leak Through Caching | Medium | Sensitive data cached by proxy/CDN | Data leak |
| CWE-525 | Sensitive Data in Browser Cache | Medium | `Cache-Control: private` missing | Local data leak |
| CWE-526 | Cleartext Transmission via Environment Variables | High | Env vars in clear over network | Credential leak |
| CWE-527 | Exposed Version-Control Repository | Critical | `.git/` exposed via web | Source, keys, config |
| CWE-528 | Exposed Core Dump | Medium | Core dump with process memory | Key material |
| CWE-529 | Exposed ACL Files | Medium | ACL config accessible | Permission info |
| CWE-530 | Exposed Backup Files | High | `.bak`, `.swp`, `~` files | Source, config |
| CWE-531 | Sensitive Info in Test Code | High | Test fixtures with real credentials | Credential leak |
| CWE-532 | Sensitive Info in Logs | High | Passwords, tokens in log files | Log-based leak |
| CWE-533 | Information Leak Through Server Log Files | Medium | Logs with user PII | Privacy violation |
| CWE-534 | Information Leak Through Debug Sources | High | Debug endpoints, verbose logging | Recon |
| CWE-535 | Information Leak Through Shell Error | Medium | Shell errors reveal path/version | Recon |
| CWE-536 | Information Leak Through Servlet Error | Medium | Servlet container error details | Recon |
| CWE-537 | Information Leak Through Java Runtime Error | Medium | JVM internals leaked | Recon |
| CWE-538 | Sensitive File Exposed to External Actor | Critical | `.env`, `.aws/credentials`, `id_rsa` exposed | Full compromise |
| CWE-539 | Persistent Cookie with Sensitive Data | Medium | Sensitive data in permanent cookie | Persistent leak |
| CWE-540 | Source Code Exposure | Critical | Raw source served instead of executed | Full recon |
| CWE-541 | Include File Source Disclosure | High | PHP source via filter wrapper | Source leak |
| CWE-542 | Debug Symbols Exposure | Medium | Binary with debug symbols | Reverse engineering |
| CWE-543 | Debug Information Exposure | Medium | Verbose debug mode in prod | Recon |
| CWE-548 | Directory Listing Exposure | Medium | Apache/Nginx directory listing | File discovery |
| CWE-549 | Password Field Not Masked | Low | Plaintext password on screen | Shoulder surfing |
| CWE-550 | Server-Side Request using Unsafe URL Scheme | High | gopher//, file://, jar:// in URL fetcher | SSRF, file read |
| CWE-551 | Incorrect Behavior Order: Early Validation | Medium | Validation after use | Logic bypass |
| CWE-552 | Exposed File/Directory | Critical | Sensitive files/dirs web-accessible | Data leak |
| CWE-553 | Command Shell Accessible Externally | Critical | phpMyAdmin, /shell, /console exposed | RCE |
| CWE-554 | ASP.NET Misconfig: Missing Input Validation | Medium | Missing validation framework | Injection |
| CWE-555 | J2EE Misconfig: Plaintext Password | Critical | Credentials in web.xml | Credential leak |

---

## CWE-10: Smart Contracts (agent: smart-contract-agent) — ~60 CWEs + SWC

Smart contract weaknesses use both CWE and the SWC (Smart Contract Weakness Classification) registry.

| CWE | SWC | Name | Severity | Detection Pattern |
|-----|-----|------|----------|-------------------|
| CWE-841 | SWC-100 | Function Default Visibility | High | `function foo() {` without explicit visibility → public |
| CWE-682 | SWC-101 | Arithmetic Overflow/Underflow | Critical | Pre-0.8.x Solidity unchecked math |
| CWE-682 | SWC-102 | Integer Overflow in Timestamp | High | `block.timestamp` math overflow |
| CWE-284 | SWC-103 | Floating Pragma | Low | `^0.8.0` instead of `0.8.19` |
| CWE-284 | SWC-104 | Unchecked Call Return Value | High | `addr.call()` without checking return |
| CWE-284 | SWC-105 | Unprotected SELFDESTRUCT | Critical | `selfdestruct()` callable by anyone |
| CWE-284 | SWC-106 | Unprotected Constructor | Critical | Typo in constructor name (pre-0.4.22) |
| CWE-682 | SWC-107 | Reentrancy (Single-Function) | Critical | State updated AFTER external call |
| CWE-682 | SWC-108 | Uninitialized State Variable | Medium | No initial value → zero address |
| CWE-682 | SWC-109 | Uninitialized Storage Pointer | High | Storage pointer in struct without init |
| CWE-682 | SWC-110 | Assert Violation | Medium | `assert()` with reachable false condition |
| CWE-682 | SWC-111 | Use of Deprecated Solidity Functions | Low | `throw`, `sha3()`, `callcode()` |
| CWE-682 | SWC-112 | Delegatecall to Untrusted Callee | Critical | `delegatecall()` with user-controlled address |
| CWE-682 | SWC-113 | DoS with Failed Call | Medium | Single failed transfer blocks all |
| CWE-682 | SWC-114 | Transaction Order Dependence | High | `block.timestamp` or `blockhash` for randomness |
| CWE-682 | SWC-115 | tx.origin Authentication | Critical | `require(tx.origin == owner)` |
| CWE-682 | SWC-116 | Block Values as Time Proxy | Medium | `block.timestamp` for time-sensitive ops |
| CWE-682 | SWC-117 | Signature Malleability | High | No check for high-s value in ECDSA |
| CWE-682 | SWC-118 | Incorrect Constructor Name | Critical | Function named like contract |
| CWE-682 | SWC-119 | Shadowing State Variables | Medium | Local var shadows storage var |
| CWE-682 | SWC-120 | Weak Randomness | Critical | `block.difficulty + block.timestamp` as entropy |
| CWE-682 | SWC-121 | Missing Protection Against Signature Replay | High | No nonce/chainId in signed message |
| CWE-682 | SWC-122 | Lack of Proper Signature Verification | Critical | ecrecover result not checked for address(0) |
| CWE-682 | SWC-123 | Requirement Violation | Medium | require() with dynamic condition |
| CWE-682 | SWC-124 | Write to Arbitrary Storage Location | Critical | User-controlled storage slot |
| CWE-682 | SWC-125 | Incorrect Inheritance Order | Medium | Diamond inheritance wrong order |
| CWE-682 | SWC-126 | Insufficient Gas Griefing | Medium | Sub-call runs out of gas |
| CWE-682 | SWC-127 | Arbitrary Jump with Function Type Variable | Critical | User-controlled function pointer |
| CWE-682 | SWC-128 | DoS Through Unexpected Revert | Medium | External call revert not handled |
| CWE-682 | SWC-129 | Typographical Error | Varies | `+=` vs `=+`, `>=` vs `=>` |
| CWE-682 | SWC-130 | Right-To-Left-Override Control Character | Medium | Unicode RTL in source → visual deception |
| CWE-682 | SWC-131 | Presence of Unused Variables | Low | Dead code / storage bloat |
| CWE-682 | SWC-132 | Ether Withdrawal Rejection | High | No withdrawal pattern, stuck funds |
| CWE-682 | SWC-133 | Hash Collisions With Multiple Variable Length Arguments | Medium | abi.encodePacked collision |
| CWE-682 | SWC-134 | Message Call with Hardcoded Gas Amount | Medium | `.call{gas: 2300}` may break on fork |
| CWE-682 | SWC-135 | Code With No Effects | Low | Dead code, self-assignment |
| CWE-682 | SWC-136 | Unencrypted Private Data On-Chain | High | "Private" data visible to all nodes |
| CWE-841 | — | Flash Loan Attack | Critical | Single-transaction price manipulation |
| CWE-841 | — | Oracle Manipulation | Critical | Thin-orderbook oracle → price manipulation |
| CWE-841 | — | Governance Attack | Critical | Flash-loaned voting power |
| CWE-841 | — | MEV (Miner Extractable Value) | High | Sandwich attack, front-running, back-running |
| CWE-841 | — | Read-Only Reentrancy | High | View function reads stale state during reentrancy |
| CWE-841 | — | Cross-Chain Replay | High | Same tx valid on multiple chains |
| CWE-841 | — | Insufficient Input Validation in Token | High | Token accepting malicious data |
| CWE-841 | — | ERC-4626 Inflation Attack | High | First depositor inflation |
| CWE-841 | — | ERC-20 approval front-run | High | `approve(100)` → front-run spend → approve(200) adds to spent |
| CWE-841 | — | EIP-712 signature phishing | High | Safe-looking typed data → malicious transaction |
| CWE-841 | — | Metamorphic Contract Attack | Critical | CREATE2 → selfdestruct → different code at same address |
| CWE-841 | — | Fee-on-Transfer Token Incompatibility | High | Token takes fee on transfer → accounting mismatch |
| CWE-841 | — | Rebasing Token Incompatibility | High | balanceOf changes without transfer |
| CWE-841 | — | Storage Collision in Upgradeable Proxy | Critical | Implementation and proxy storage layout mismatch |
| CWE-841 | — | Uninitialized Proxy Implementation | Critical | UUPS/Transparent proxy has no implementation |
| CWE-841 | — | Function Clashing in Proxy | High | Proxy and impl have same function selector |
| CWE-841 | — | Rounding Error Accumulation | Medium | D0/1 rounding direction consistent → value leak |
| CWE-841 | — | Slippage Without Deadline | High | `block.timestamp` deadline → MEV |
| CWE-841 | — | Sandwich-Resistant but not Front-Running-Resistant | Medium | Single-mechanism protection |
| CWE-841 | — | Unchecked External Return in Multicall | High | One failed call in batch silences others |
| CWE-841 | — | TWAP Oracle Manipulation | Critical | Short TWAP window manipulation |
| CWE-841 | — | Insufficient Access Control on initialize() | Critical | `initializer` modifier missing → anyone re-inits |

---

## CWE-11: Network & Infrastructure (agent: recon-agent) — ~50 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-200 | Banner Grabbing Version Disclosure | Low | Server: Apache/2.4.6, X-Powered-By: PHP/5.3 | Recon |
| CWE-203 | User Enumeration via Response | Medium | "User exists" vs "Invalid password" | User list |
| CWE-204 | Username Enumeration via Timing | Low | Timing side-channel for user existence | User list |
| CWE-295 | Missing/Improper Certificate Validation | High | Self-signed cert, wrong hostname | MITM |
| CWE-297 | Certificate Hostname Mismatch | Medium | cert for a.com on b.com | MITM |
| CWE-311 | Missing HSTS Header | Medium | No Strict-Transport-Security | Downgrade attack |
| CWE-319 | HTTP Without TLS | High | Login/API over cleartext HTTP | Credential sniffing |
| CWE-322 | Key Exchange Without Auth | Critical | Anonymous Diffie-Hellman | MITM |
| CWE-326 | Weak TLS Cipher Suites | High | RC4, 3DES, EXPORT ciphers enabled | Cipher downgrade |
| CWE-327 | Weak TLS Protocol Version | High | SSLv3, TLS 1.0, TLS 1.1 | POODLE, BEAST |
| CWE-346 | Missing CORS Validation | Medium | Access-Control-Allow-Origin: * with creds | Cross-origin data theft |
| CWE-352 | Missing CSRF Protection | High | No CSRF token on state-changing POST | Forged requests |
| CWE-400 | Uncontrolled Resource Consumption | Medium | No request size limit → memory exhaustion | DoS |
| CWE-521 | Weak Password Policy | Medium | No complexity, minimum length 1 | Credential brute force |
| CWE-523 | Unprotected Credential Transport | Critical | No TLS on login endpoint | Credential sniffing |
| CWE-525 | Missing Cache-Control Headers | Low | Sensitive pages cached in browser | Local data leak |
| CWE-538 | Exposed Sensitive Files | Critical | `.env`, `Dockerfile`, `.git/config` exposed | Credential leak |
| CWE-552 | Exposed Admin Interfaces | Critical | `/admin`, `/phpmyadmin`, `/actuator` exposed | Full compromise |
| CWE-554 | Missing Security Headers | Low | No CSP, X-Frame-Options, X-Content-Type-Options | Defense-in-depth |
| CWE-601 | Open Redirect | Medium | `redirect=` param without validation | Phishing |
| CWE-614 | Missing Secure Cookie Flag | Medium | Auth cookie without Secure flag | Cookie theft |
| CWE-693 | Missing Protection Mechanism | Varies | No rate limiting, no WAF, no IDS | Attack surface |
| CWE-778 | Insufficient Logging | Medium | No audit log of auth events | Attack invisible |
| CWE-779 | Excessive Logging of Sensitive Data | Medium | Full PII/credentials in logs | Log data leak |
| CWE-798 | Default Credentials | Critical | admin:admin, root:root | Full compromise |
| CWE-804 | Weak CAPTCHA | Medium | Easily OCR'd/no challenge variety | Automated abuse |
| CWE-838 | Improper Output Encoding | Medium | Encoding mismatch → injection | XSS, injection |
| CWE-862 | Missing Authorization | Critical | No access control on API | Unauthorized access |
| CWE-916 | Weak Password Hashing | High | No salt, single iteration, MD5/SHA1 | Credential cracking |
| CWE-918 | SSRF via Infrastructure Misconfig | Critical | Metadata endpoint accessible from app | Cloud cred theft |
| CWE-920 | Improper Restriction of Power Consumption | Low | No rate limit → high CPU usage | DoS |
| CWE-921 | Storage Without Access Control | Critical | S3 bucket public, Azure blob public | Data exposure |
| CWE-922 | Insecure Storage | Critical | Unencrypted S3 bucket with PII | Data exposure |
| CWE-923 | Improper Channel Access Restriction | High | Internal service on public IP | Internal access |
| CWE-1038 | Insecure Automated Optimizations | Low | Auto-minify removing security comments | CSP bypass |
| CWE-1041 | Multi-Path Issues | Medium | Same resource via multiple paths with different controls | Auth bypass |
| CWE-1042 | Static Member Data Element outside of Singleton Class | Low | Shared state across instances | State confusion |
| CWE-1043 | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | Low | God object with everything | Performance |
| CWE-1044 | Architecture with Number of Horizontal Layers Outside of Expected Range | Low | Too many abstraction layers | Performance |
| CWE-1045 | Parent Class with Virtual Function Called in Constructor | Medium | Virtual dispatch before full init | Undefined behavior |
| CWE-1046 | Immutable String Concatenation in Loop | Low | String concat in loop → O(n²) | DoS |
| CWE-1047 | Modules Following Different Architectures | Low | Inconsistent architecture | Maintenance |
| CWE-1048 | Invokable Control Element with Large Number of Outward Calls | Medium | God class → tight coupling | Side effects |
| CWE-1049 | Excessive Data Query Operations in a Large Data Table | Low | N+1 query problem | DoS |
| CWE-1050 | Excessive Platform Resource Consumption within a Loop | Medium | Resource allocation in loop | DoS |
| CWE-1051 | Excessive Iteration in Initialization | Low | Heavy init blocking startup | DoS |
| CWE-1052 | Excessive Use of Unnecessary Escape Characters | Low | Over-escaping | Performance |
| CWE-1053 | Missing Documentation for Design | Low | No security design doc | Unknown risk |
| CWE-1054 | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | Low | Too deep call stack | Performance |
| CWE-1055 | Multiple Inheritance from Concrete Classes | Low | Diamond problem | Logic error |
| CWE-1056 | Invokable Control Element with Variadic Parameters | Low | Variadic without type safety | Injection |
| CWE-1057 | Data Access Operations Outside of Expected Data Manager Component | Medium | Direct DB access bypassing ORM | SQL injection |
| CWE-1058 | Invokable Control Element in Multi-Thread Context with Improper Locking | High | Thread-unsafe singleton | Race condition |
| CWE-1059 | Insufficient Technical Documentation | Low | No API docs → hidden endpoints | Unknown surface |
| CWE-1060 | Excessive Number of Inefficient Server-Side Data Accesses | Medium | Too many DB queries per request | DoS |
| CWE-1061 | Insufficient Encapsulation | Medium | Internal data leaked through API | Information leak |
| CWE-1062 | Parent Class with References to Child Class | Low | Circular dependency | Maintenance |
| CWE-1063 | Creation of Immutable Objects Using Shortcuts | Low | Incomplete initialization | Logic error |
| CWE-1064 | Invokable Control Element with Signature Containing an Unnecessary Parameter | Low | Extra params → confusion | Logic error |
| CWE-1065 | Runtime Resource Management in Unmanaged Code | Medium | Memory/thread leak in native code | Resource exhaustion |
| CWE-1066 | Missing Serialization Control | Medium | Sensitive field serialized | Information leak |
| CWE-1067 | Excessive Execution of Sequential Searches of Data Resource | Low | Linear search in hot path | DoS |

---

## CWE-12: CI/CD & Supply Chain (agent: supply-chain-agent) — ~35 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-427 | Uncontrolled Search Path Element | High | DLL/SO hijacking via PATH | RCE on build |
| CWE-494 | Download of Code Without Integrity Check | Critical | `curl | bash`, no checksum verification | RCE |
| CWE-506 | Embedded Malicious Code | Critical | Malicious code in dependency | Full compromise |
| CWE-509 | Replicating Malicious Code | Critical | Virus/worm in supply chain | Full compromise |
| CWE-510 | Trapdoor (Backdoor) | Critical | Intentional hidden access | Full compromise |
| CWE-511 | Logic/Time Bomb | Critical | Code dormant until trigger | Delayed compromise |
| CWE-512 | Spyware | Critical | Data exfiltration code | Data theft |
| CWE-514 | Covert Channel | Medium | Hidden data channel | Data exfil |
| CWE-520 | .NET Misconfiguration: Use of Impersonation | Medium | Excessive impersonation | Privilege escalation |
| CWE-521 | Weak Password Requirements | Medium | Weak CI/CD secrets | Credential compromise |
| CWE-522 | Insufficiently Protected Credentials | Critical | CI/CD secrets in plaintext | Credential leak |
| CWE-523 | Unprotected Transport of Credentials | Critical | Secrets over HTTP in pipeline | Credential sniffing |
| CWE-547 | Hard-coded Security-Relevant Constants | High | Hardcoded API keys in pipeline | Credential leak |
| CWE-552 | Exposed CI/CD Dashboard | Critical | Jenkins/GitHub Actions/Drone exposed | Pipeline hijack |
| CWE-565 | Reliance on Cookies Without Validation | Medium | Session hijack on CI/CD UI | Pipeline access |
| CWE-611 | XXE in CI/CD Config | Critical | XXE in XML-based CI configs | File read, SSRF |
| CWE-798 | Hard-coded Credentials in Pipeline | Critical | `GH_TOKEN=ghp_...` in workflow yml | Token theft |
| CWE-807 | Untrusted Input in Build Script | Critical | PR title/body in shell command | RCE on builder |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | Critical | Third-party action at mutable ref | Supply chain |
| CWE-830 | Inclusion of Web Functionality from Untrusted Source | High | Script src from CDN without integrity | Supply chain |
| CWE-912 | Hidden Functionality in CI/CD | Critical | Backdoor in build process | Full compromise |
| CWE-913 | Dynamic Code in Build | Critical | `eval()` in build script | RCE on builder |
| CWE-914 | Dynamically-Identified Variables in Pipeline | High | Variable interpolation from PR | Command injection |
| CWE-915 | Mass Assignment in Pipeline Config | High | Overwrite pipeline variables | Pipeline hijack |
| CWE-916 | Weak Secrets in CI/CD | High | Short/weak CI/CD secrets | Brute force |
| CWE-940 | Improper Verification of Communication in CI/CD | High | No verification of artifact origin | Artifact poisoning |
| CWE-1104 | Use of Unmaintained Third Party Components | High | Abandoned npm/pip/gem package | Known vulns |
| CWE-1108 | Excessive Reliance on Global Variables | Medium | Global state in build | Build pollution |
| CWE-1109 | Use of Same Cryptographic Key for Multiple Purposes | Medium | Same key for CI/CD + prod | Key compromise |
| CWE-1270 | Generation of Incorrect Security Tokens | High | Weak CI/CD token generation | Token forgery |
| CWE-1271 | Unencrypted Sensitive Data on Disk | Critical | CI/CD secrets on disk in plaintext | Credential theft |
| CWE-1272 | Sensitive Data in Environment Variables | High | Secrets in `/proc/self/environ` | Credential leak |
| CWE-1273 | Sensitive Data in Command-Line Arguments | High | `-e MYSQL_ROOT_PASSWORD=...` in docker run | Credential leak |
| CWE-1274 | Improper Handling of Highly Compressed Data in CI/CD | Medium | Zip bomb in artifact | DoS |
| CWE-1275 | Cookie with Overly Broad Domain in CI/CD UI | Low | Session cookie for *.ci.internal | Session hijack |
| CWE-1276 | Improper Neutralization of Formula Elements in CSV Export | High | CSV injection in build reports | RCE when opened |
| CWE-1277 | Firmware Not Updateable | Low | Immutable firmware | Patching impossible |
| CWE-1278 | Immutable Root of Trust in Firmware | Low | Cannot update trust anchor | Long-term risk |
| CWE-1279 | Cryptographic Operations Run Before Initialization | Medium | Crypto before PRNG seeded | Weak crypto |
| CWE-1280 | Improper Access Control to Debug/Test Interfaces in CI/CD | High | Debug port on builder | Pipeline access |
| CWE-1281 | Improperly Controlled Sequential Memory Allocation | Low | Fragmentation attack | DoS |
| CWE-1282 | Assumed-Immutable Build Artifact | High | Artifact modified between build and deploy | Supply chain |

### GitHub Actions Specific
| CWE | Name | Severity | Detection Pattern |
|-----|------|----------|-------------------|
| CWE-94 | Expression Injection in `run:` | Critical | `${{ github.event.issue.title }}` in shell |
| CWE-494 | Untrusted Checkout (no ref) | High | `uses: actions/checkout@v4` without ref pin |
| CWE-829 | Unpinned Action Version | High | `uses: some/action@main` (mutable) |
| CWE-269 | Workflow_run Privilege Escalation | Critical | `workflow_run` from fork → secrets access |
| CWE-346 | Artifact Poisoning | High | Attacker uploads artifact consumed by privileged workflow |
| CWE-862 | Missing `permissions:` Block | High | Default `write-all` GITHUB_TOKEN |
| CWE-532 | Secret in Step Output | High | `echo "::set-output name=token::$SECRET"` |
| CWE-200 | Repository Disclosure via Actions | Medium | Actions log reveals source/config |

---

## CWE-13: Mobile (agent: mobile-client-agent) — ~40 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-200 | Sensitive Data in Shared Preferences (Android) | High | MODE_WORLD_READABLE, no encryption | Data leak |
| CWE-200 | Sensitive Data in NSUserDefaults (iOS) | High | Plist without encryption | Data leak |
| CWE-200 | Sensitive Data in App Directory | High | SQLite DB with tokens/PII without encryption | Data leak |
| CWE-259 | Hardcoded Password in Mobile App | Critical | String search for password=, api_key=, secret= | Credential theft |
| CWE-295 | Missing SSL Certificate Pinning | High | Accepts any certificate → MITM | Traffic interception |
| CWE-297 | Improper Hostname Verification | High | Custom HostnameVerifier returning true | MITM |
| CWE-311 | Missing Encryption at Rest | Critical | No file/db encryption on device | Data theft |
| CWE-312 | Cleartext Storage of Sensitive Information | Critical | Tokens in plaintext files | Token theft |
| CWE-319 | Cleartext Traffic (HTTP) | Critical | HTTP for API calls | Credential sniffing |
| CWE-321 | Hardcoded Cryptographic Key | Critical | Encryption key in source | Decryption by attacker |
| CWE-326 | Weak Encryption on Device | High | DES, RC4 for local data | Decryption feasible |
| CWE-327 | Use of Broken Crypto in App | High | MD5, SHA1 for integrity | Bypass integrity check |
| CWE-330 | Weak Random in Mobile | High | java.util.Random for tokens | Token prediction |
| CWE-359 | PII Exposure via App | Critical | Address book, location, photos leaked | Privacy violation |
| CWE-470 | Use of Externally-Controlled Input to Select Classes or Code | Critical | Class.forName from intent extra | RCE |
| CWE-489 | Active Debug Code in Production | High | `android:debuggable="true"`, debug endpoints | Full compromise |
| CWE-501 | Trust Boundary Violation in IPC | High | Intent data from untrusted app | Privilege escalation |
| CWE-522 | Hardcoded Credentials in Binary | Critical | Strings in .so/.dylib, resources | Credential extraction |
| CWE-524 | Sensitive Data in Cache | Medium | WebView cache, okhttp cache with tokens | Token theft |
| CWE-525 | Sensitive Data in WebView Cache | Medium | WebView with tokens in cache | Token theft |
| CWE-532 | Sensitive Data in Logcat/NSLog | High | `Log.d("token", authToken)` | Log-based leak |
| CWE-538 | Sensitive File in App Bundle | High | .plist, .json with creds in IPA/APK | Credential leak |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Critical | Root/jailbreak detection bypassable | Cheating |
| CWE-749 | Exposed Dangerous Method or Function | High | Exported WebView, JS interfaces | XSS → RCE |
| CWE-798 | Hardcoded API Keys | Critical | Google Maps, Stripe, AWS keys in app | Key abuse |
| CWE-804 | Weak Biometric Authentication | Medium | Fingerprint without crypto-backed keystore | Biometric bypass |
| CWE-838 | Improper WebView Configuration | High | JavaScript enabled, file access enabled | XSS, file access |
| CWE-862 | Missing Authorization on Exported Activity | Critical | Exported activity without permission | Privilege escalation |
| CWE-863 | Incorrect Authorization on Content Provider | Critical | Content provider without read/write permission | Data theft |
| CWE-921 | Sensitive Data in External Storage | High | SD card / shared storage with PII | Data theft |
| CWE-922 | Insecure Data Storage | Critical | No Keychain/Keystore usage | Credential theft |
| CWE-925 | Improper Verification of Intent by Broadcast Receiver | High | Broadcast receiver without sender validation | Intent spoofing |
| CWE-926 | Improper Export of Android Application Components | High | Activity/Service/Receiver exported without need | Attack surface |
| CWE-927 | Implicit Intent for Sensitive Communication | Medium | Sensitive data in implicit intent | Data leak to other apps |
| CWE-928 | Improper Authorization for Broadcast Receiver | High | No permission on exported receiver | Intent injection |
| CWE-939 | Improper Authorization in Custom URL Scheme Handler | High | Custom URL scheme without validation | Action spoofing |
| CWE-940 | Improper Source Verification of IPC | High | No check of calling package/UID | Privilege escalation |
| CWE-953 | Improper Rest of APK Signature Verification | Medium | Weak signature check | APK tampering |

### Mobile-Specific Attack Patterns
| Pattern | Platform | Detection |
|---------|----------|-----------|
| Deep link hijacking | Android/iOS | Custom scheme without validation |
| Task hijacking (taskAffinity) | Android | `taskAffinity` without `singleInstance` |
| Strandhogg | Android | Task reparenting to phishing overlay |
| WebView JavaScript Interface abuse | Android | `addJavascriptInterface` with `@JavascriptInterface` |
| WebView file access | Android | `setAllowFileAccess(true)` + `loadUrl(file://)` |
| Biometric bypass without Keychain/Keystore | Android/iOS | Biometric without `setUserAuthenticationRequired(true)` |
| Firebase database open | Android/iOS | `.read: true, .write: true` in Firebase rules |
| App screenshot/screen recording | Android/iOS | `FLAG_SECURE` missing in sensitive screens |
| Push notification hijacking | Android/iOS | FCM/APNs token in plaintext |
| Deeplink to internal component | Android | Deep link → exported activity without auth |
| App clip / Instant app bypass | Android/iOS | Instant app without full auth |
| Insecure file provider | Android | FileProvider with `android:exported="true"` |
| Shared UID vulnerability | Android | `android:sharedUserId` across apps |

---

## CWE-14: Cloud & Container (agent: recon-agent) — ~35 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-200 | Cloud Metadata Exposure | Critical | `http://169.254.169.254/latest/meta-data/` accessible | IAM credential theft |
| CWE-269 | Overly Permissive IAM Role | Critical | `s3:*`, `iam:*`, `*:*` policies | Full cloud compromise |
| CWE-276 | Public S3 Bucket | Critical | Bucket with `s3:GetObject` for `*` | Data exposure |
| CWE-276 | Public ECR/ACR/GCR Repository | High | Container image world-readable | Source leak |
| CWE-276 | Public EBS Snapshot | High | Snapshot shared publicly | Data recovery |
| CWE-276 | Public RDS Snapshot | Critical | Database snapshot public | Full DB leak |
| CWE-276 | Public AMI | Medium | Custom AMI with baked-in secrets | Credential leak |
| CWE-284 | Missing Bucket Policy | Critical | No bucket policy → default may be permissive | Data exposure |
| CWE-311 | Unencrypted S3 Bucket | High | No default encryption, no SSE | Data exposure at rest |
| CWE-311 | Unencrypted EBS Volume | High | No KMS encryption on volumes | Data exposure |
| CWE-311 | Unencrypted RDS | High | No encryption at rest on DB | Data exposure |
| CWE-319 | Unencrypted Cloud Traffic | Medium | HTTP between cloud services | Traffic interception |
| CWE-521 | Weak IAM Password Policy | Medium | No MFA, no password rotation | Account compromise |
| CWE-522 | Hardcoded Cloud Credentials | Critical | AWS keys in source, env vars, CI/CD | Full cloud access |
| CWE-522 | IAM Access Key Age | Medium | Access keys > 90 days old | Key compromise risk |
| CWE-532 | CloudTrail Logging Disabled | Medium | No API logging | Attack invisible |
| CWE-538 | Exposed .docker/config.json | Critical | Docker credentials exposed | Registry access |
| CWE-552 | Exposed Kubernetes Dashboard | Critical | K8s dashboard without auth | Cluster admin |
| CWE-552 | Exposed etcd | Critical | etcd port 2379 open | Cluster secrets |
| CWE-552 | Exposed Kubelet API | Critical | Port 10250 open | Pod exec, secret access |
| CWE-552 | Exposed Docker API | Critical | Port 2375/2376 without TLS/auth | Container escape |
| CWE-668 | Cross-Tenant Access in Cloud | Critical | Resource in wrong account accessible | Cross-account access |
| CWE-693 | Missing WAF/Shield | Medium | No DDoS protection | DoS |
| CWE-732 | Overly Permissive Security Group | High | 0.0.0.0/0 on SSH/RDP/DB ports | Unauthorized access |
| CWE-732 | Overly Permissive NACL | Medium | No deny rules | Loose network control |
| CWE-778 | Missing CloudTrail | High | No API activity logging | Forensics impossible |
| CWE-798 | Default IAM Credentials | Critical | Root account without MFA | Full account compromise |
| CWE-862 | Missing Service Control Policy | High | No SCP on organization accounts | Account escape |
| CWE-862 | Lambda:Missing Function Policy | Medium | Lambda invocable by anyone | DoS, data access |
| CWE-918 | SSRF to Cloud Metadata | Critical | App → 169.254.169.254 → IAM creds | Cloud account takeover |
| CWE-921 | S3 Bucket Without Access Logging | Medium | No access logs on sensitive bucket | Forensics gap |
| CWE-922 | Insecure Lambda Environment Variables | High | Secrets in Lambda env vars | Credential leak |
| CWE-1004 | Sensitive Cookie Without SameSite Attribute | Low | Cookie not samesite | CSRF |
| CWE-1038 | Insecure Automated Optimizations in Cloud | Low | Auto-minification removing security config | Security bypass |
| CWE-1244 | Debug Access to Cloud Resources | High | SSM/SSH debug access without auth | Unauthorized access |
| CWE-1271 | K8s Secret in Plaintext etcd | Critical | etcd without encryption at rest | Secret theft |
| CWE-1272 | Sensitive Information in Environment Variables in Container | High | `docker inspect` reveals env vars | Credential leak |
| CWE-1280 | K8s RBAC Misconfiguration | Critical | `cluster-admin` for default service account | Full cluster access |

---

## CWE-15: GraphQL (agent: graphql-agent) — ~20 CWEs

| CWE | Name | Severity | Detection Pattern |
|-----|------|----------|-------------------|
| CWE-200 | GraphQL Introspection Enabled | Medium | `__schema` query accessible → full API map |
| CWE-200 | GraphQL Field Suggestion Leak | Low | Error: "Did you mean 'adminField'?" |
| CWE-89 | GraphQL SQL Injection | Critical | Arguments passed directly to SQL |
| CWE-94 | GraphQL Code Injection | Critical | Resolver with eval/exec |
| CWE-287 | GraphQL Missing Authentication | Critical | No auth on mutations/queries |
| CWE-400 | GraphQL Batching Attack | High | Send same expensive query × 100 in batch |
| CWE-400 | GraphQL Alias-Based DoS | High | `a1:field, a2:field, ..., a10000:field` |
| CWE-400 | GraphQL Circular Fragment DoS | Medium | `{ ...A } fragment A { ...B } fragment B { ...A }` |
| CWE-400 | GraphQL Deep Nesting DoS | High | `{a{b{c{d{e{f{g{h{i{j{field}}}}}}}}}}}` |
| CWE-639 | GraphQL IDOR | Critical | Query other user's data via ID field |
| CWE-770 | GraphQL Array-Based DoS | Medium | `{field(arg: [1,2,3,...,10000])}` |
| CWE-862 | GraphQL Missing Field-Level Authorization | Critical | Some fields resolvable without proper authz |
| CWE-863 | GraphQL Incorrect Authorization | High | Role check missing on mutation |
| CWE-915 | GraphQL Mass Assignment | High | `mutation { updateUser(id:1, role:"admin")}` |
| CWE-918 | GraphQL SSRF | Critical | Resolver makes HTTP request with user-controlled URL |
| — | GraphQL GET-based CSRF | High | Mutations accepted via GET with query params |
| — | GraphQL Subscriptions without Auth | Medium | Websocket subscription leaks real-time data |
| — | GraphQL Directive Overloading | Medium | `@skip`, `@include` abuse → bypass |
| — | GraphQL Persisted Query Abuse | Medium | Send spoofed persisted query hash |
| — | GraphQL File Upload Bypass | High | Multipart upload spec bypasses query validation |

---

## CWE-16: HTTP Smuggling & Cache Poisoning (agents: http-smuggling-agent + cache-poisoning-agent) — ~20 CWEs

| CWE | Name | Severity | Detection Pattern | Impact |
|-----|------|----------|-------------------|--------|
| CWE-444 | HTTP Request Smuggling (CL.TE) | Critical | Content-Length + Transfer-Encoding mismatch | Session hijack, WAF bypass |
| CWE-444 | HTTP Request Smuggling (TE.CL) | Critical | TE declares chunked but CL used by frontend | Session hijack |
| CWE-444 | HTTP Request Smuggling (TE.TE) | High | Multiple TE headers with different parsing | WAF bypass |
| CWE-444 | HTTP/2 Downgrade Smuggling | Critical | H2 → H1.1 downgrade injection | Request smuggling |
| CWE-444 | HTTP/2 HPACK Bomb | Medium | Compressed header DoS | Resource exhaustion |
| CWE-436 | Content Spoofing via Content-Type | Medium | text/html served as text/plain → XSS | XSS |
| CWE-437 | Incomplete Model of Endpoint Features | Medium | Parser disagreement between frontend/backend | Smuggling |
| CWE-438 | Behavioral Problems | Medium | Inconsistent behavior under edge conditions | Smuggling |
| CWE-444 | CL.0 Request Smuggling | Critical | Backend ignores CL when frontend doesn't send | Smuggling |
| CWE-444 | HTTP/1.0 Smuggling | High | Connection: keep-alive confusion | Smuggling |
| — | Web Cache Poisoning (Unkeyed Input) | High | X-Forwarded-Host, X-Forwarded-Scheme unkeyed | Stored XSS in cache |
| — | Web Cache Poisoning (Unkeyed Method) | Medium | GET keyed but X-HTTP-Method-Override unkeyed | Method override |
| — | Web Cache Poisoning (Unkeyed Query) | High | Query string unkeyed → parameter injection in cache | Stored XSS |
| — | Web Cache Poisoning (Fat GET) | Medium | Request body on GET unkeyed | Cache confusion |
| — | Web Cache Deception | High | `profile.css` → cache stores full profile page | PII in cache |
| — | Web Cache Deception (Path Confusion) | High | `nonexistent/path/..%2Fprofile` caches as static | PII in cache |
| — | Web Cache Deception (Delimiter) | Medium | `profile;.css`, `profile%0d%0a.css` caches as static | PII in cache |
| — | Host Header Poisoning | High | `Host: evil.com` caches with attacker's host | Phishing |
| — | X-Forwarded-Host Poisoning | High | `X-Forwarded-Host: evil.com` → poison links in cache | Phishing |
| — | Relative Path Overwrite (RPO) | Medium | Path-relative stylesheet → CSS injection | CSS-based attack |

---

## Agent-to-CWE Quick Index

| Agent | Primary CWE Ranges | Count |
|-------|-------------------|-------|
| web-api-agent | CWE-22..59, CWE-77..98, CWE-79..87, CWE-89..91, CWE-94..98, CWE-120..197, CWE-415..825, CWE-918 | ~280 |
| access-control-agent | CWE-250..305, CWE-345..384, CWE-472..670, CWE-708..1293 | ~170 |
| crypto-math-agent | CWE-310..351, CWE-522..548, CWE-759..780, CWE-916 | ~90 |
| business-logic-agent | CWE-1284..1292, CWE-472, CWE-602, CWE-784, CWE-807, CWE-830..915 | ~50 |
| race-condition-agent | CWE-362..414, CWE-543..820, CWE-1084 | ~35 |
| smart-contract-agent | CWE-682, CWE-841 + SWC-100..136 | ~60 |
| recon-agent | CWE-200..552, CWE-693..1041 | ~110 |
| credential-leak-agent | CWE-200, CWE-259, CWE-312..548, CWE-798 | ~60 |
| supply-chain-agent | CWE-427, CWE-494..1282 | ~40 |
| http-smuggling-agent | CWE-436..444 | ~10 |
| cache-poisoning-agent | CWE-436..444 (cache variant) | ~10 |
| graphql-agent | CWE-89..918 (GraphQL variants) | ~20 |
| mobile-client-agent | CWE-200..953 (mobile variants) | ~40 |
| waf-bypass-agent | CWE-79, CWE-89, CWE-918 (bypass techniques) | ~15 |

**Total unique CWEs covered: 1,047**
