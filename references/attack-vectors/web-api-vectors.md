# Web / API Attack Vectors

Quick reference for all major web and API attack classes.

## Authentication
- JWT `alg:none`, weak secret, expired token acceptance
- OAuth: state CSRF, redirect_uri manipulation, token leakage in referrer
- Password reset: host header injection in reset link, predictable token, no expiry, concurrent reuse
- Session fixation, session riding, session not invalidated on logout
- Email confirmation bypass: confirmation sent to old email instead of new email → account takeover via SSO
- Session cookie theft via HTTP request smuggling (CL.TE desync → redirect → cookie exfil)

## Authorization
- IDOR: horizontal (peer resources), vertical (admin resources)
- Mass assignment: undocumented fields (`role`, `is_admin`, `balance`)
- Function-level auth: middleware checks but handler does not
- GraphQL: missing auth on mutations, IDOR in node IDs, batch query abuse
- Tenant isolation failures in multi-tenant SaaS
- Email confirmation bypass → SSO takeover → full privilege escalation

## Injection
- SQLi: error-based, time-based, UNION, blind
- CSV injection: leading `=`, `+`, `-`, `@` in exported spreadsheet fields
- SSTI: Jinja2, Twig, FreeMarker, Velocity
- SpEL Injection: Spring Expression Language — `${7*7}` in error pages, `${T(java.lang.Runtime)}` for RCE, Akamai WAF bypass via character-by-character ASCII construction without quotes
- Command injection: `;`, `|`, `$()`
- XXE: SYSTEM entity, OOB via external DTD
- SSRF: cloud metadata, internal network, localhost
- Path traversal: `../`, `....//`, upload/download file path abuse
- Open redirect: unvalidated `next`, `return_url`, `redirect_uri` parameters
- Parameter pollution: duplicate query/form params, array/scalar collisions, header/value mismatches
- OS command injection via web application parameters (IP fields, lookup tools)

## Cross-Site
- XSS: reflected, stored, DOM; SVG upload, Markdown renderer
- XSS WAF Bypass: Unicode escapes (\u0061), HTML entities (&#106), optional chaining (?.), comment splitting (/**/), string concatenation ('ale'+'rt'), AutoFocus+OnFocus chaining, regex source (/al/.source+/ert/.source), dynamic import() exfil, form feed (%0C) + tab (%09) whitespace, multi-element assembly via location=, contenteditable+onbeforeinput, array indexing chars, double URL encoding (%252F)
- Blind XSS: fetch('/admin') → btoa() → new Image().src exfiltration chain for admin page content theft
- CSRF: missing token, SameSite not set
- CORS: wildcard with credentials, null origin accepted
- Host header injection: reset link, cache poisoning
- Blind XSS on image upload (admin panel rendering)
- Stored XSS via cache poisoning on authentication pages
- XSS in game client / chat interface leading to RCE

## Business Logic
- Negative/zero quantities
- Coupon stacking
- Workflow step skip
- Rate limit bypass via headers
- Email confirmation bypass → set master password for all accounts
- Payment in-flight data modification
- CD key / license key extraction via API manipulation

## Advanced
- HTTP request smuggling: CL.TE, TE.CL → session hijack → mass account takeover
- Cache poisoning: X-Forwarded-Host, X-Original-URL → stored XSS on sensitive pages
- Subdomain takeover: CNAME to unclaimed cloud asset → authentication bypass
- WebSocket: missing auth on upgrade, CSWSH
- Deserialization: Java, PHP, Python pickle, PHP object injection in cookies
- Supply chain: npm/Gem/PyPI package name squatting → RCE on install
- Git flag injection: malicious filenames in repo import → file overwrite → RCE
- Project import: path traversal in file copy operations → arbitrary file read

## Infrastructure Misconfiguration
- Exposed CI/CD: Jenkins, CircleCI, GitLab CI without authentication
- Exposed monitoring: Grafana dashboards with internal metrics and credentials
- Exposed Kubernetes API: no auth → full cluster access → container RCE
- Exposed Spring Actuators: /actuator/env leaks secrets, /actuator/heapdump for memory analysis
- Exposed admin panels: Jira, Confluence, Phabricator from leaked certificates

## Credential & Secret Exposure
- GitHub tokens in compiled apps (.env in Electron .asar files)
- API keys in JavaScript bundles
- Tokens in CI/CD build logs (Travis CI, GitHub Actions)
- Docker Hub tokens in environment variables
- Hardcoded credentials in public repositories
- Leaked certificates granting access to internal services

## Information Disclosure
- Stack traces, DB errors
- API keys in JS bundles / git history
- GraphQL introspection on production — mass PII exfil via missing field-level auth
- Backup files: `.bak`, `.old`, `.swp`, `.git/`
- JWT claims with internal data
- Memory content disclosure in webmail clients
