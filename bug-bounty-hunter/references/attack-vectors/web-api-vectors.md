# Web / API Attack Vectors

Quick reference for all major web and API attack classes.

## Authentication
- JWT `alg:none`, weak secret, expired token acceptance
- OAuth: state CSRF, redirect_uri manipulation, token leakage in referrer
- Password reset: host header injection in reset link, predictable token, no expiry, concurrent reuse
- Session fixation, session riding, session not invalidated on logout

## Authorization
- IDOR: horizontal (peer resources), vertical (admin resources)
- Mass assignment: undocumented fields (`role`, `is_admin`, `balance`)
- Function-level auth: middleware checks but handler does not
- GraphQL: missing auth on mutations, IDOR in node IDs, batch query abuse
- Tenant isolation failures in multi-tenant SaaS

## Injection
- SQLi: error-based, time-based, UNION, blind
- SSTI: Jinja2, Twig, FreeMarker, Velocity
- Command injection: `;`, `|`, `$()`
- XXE: SYSTEM entity, OOB via external DTD
- SSRF: cloud metadata, internal network, localhost

## Cross-Site
- XSS: reflected, stored, DOM; SVG upload, Markdown renderer
- CSRF: missing token, SameSite not set
- CORS: wildcard with credentials, null origin accepted
- Host header injection: reset link, cache poisoning

## Business Logic
- Negative/zero quantities
- Coupon stacking
- Workflow step skip
- Rate limit bypass via headers

## Advanced
- HTTP request smuggling: CL.TE, TE.CL
- Cache poisoning: X-Forwarded-Host, X-Original-URL
- Subdomain takeover: CNAME to unclaimed cloud asset
- WebSocket: missing auth on upgrade, CSWSH
- Deserialization: Java, PHP, Python pickle

## Information Disclosure
- Stack traces, DB errors
- API keys in JS bundles / git history
- GraphQL introspection on production
- Backup files: `.bak`, `.old`, `.swp`, `.git/`
- JWT claims with internal data
