# Trust Map

Who trusts whom. The attack surface.

See also: [[BountyForge]], [[Methodology]], [[Web2 Recon]], [[Vuln Classes]], [[A→B Chains]]

---

## What Is a Trust Boundary?

Every bug is a trust violation. The system trusted something it shouldn't have:
- **Identity** it shouldn't have → IDOR, privilege escalation, auth bypass
- **State** it shouldn't have → race conditions, TOCTOU, state machine bypass
- **Input** it shouldn't have → injection, deserialization, SSTI
- **Intent** it shouldn't have → business logic abuse, economic manipulation

**Map trust first. Hunt violations second.**

---

## Trust Endpoint Categories

| Category | Examples | Bug Classes |
|----------|----------|-------------|
| **Identity trust** | Auth tokens, session cookies, API keys, JWT claims, OAuth flows | IDOR, auth bypass, session hijack |
| **Input trust** | User params, headers, body, file uploads | XSS, SQLi, SSRF, SSTI, XXE |
| **State trust** | Database records, cache, file system | Race conditions, TOCTOU, replay |
| **Service trust** | Webhooks, APIs, oracles, payment processors | SSRF, signature bypass, replay |
| **User trust** | Fingerprints, User-Agent, IPs, referrer | Spoofing, header injection |

---

## The Trust Graph

```
                    ┌─────────────┐
                    │   CLIENT    │
                    │  (browser)  │
                    └──────┬──────┘
                           │
                    trust: token/cookie
                           │
                           ▼
                    ┌─────────────┐
                    │     CDN     │
                    │  (Cloudflare)│
                    └──────┬──────┘
                           │
                    trust: X-Forwarded-For
                           │
                           ▼
                    ┌─────────────┐
                    │ LOAD BALANCER│
                    └──────┬──────┘
                           │
                    trust: internal network
                           │
                           ▼
                    ┌─────────────┐
                    │  APP SERVER  │
                    └──────┬──────┘
                           │
                    trust: SQL query
                           │
                           ▼
                    ┌─────────────┐
                    │  DATABASE    │
                    └─────────────┘
```

**Every arrow is a trust boundary. Every boundary is an attack surface.**

---

## Building the Trust Map

1. **Identify all trust endpoints** from recon. See [[Web2 Recon]].
2. **Draw edges** between entities (client, CDN, LB, app, DB, third-party).
3. **Label each edge** with trust type: `token_based`, `header_based`, `ip_based`, `no_auth`, `signature`.
4. **Find crossings** — where does trust cross from outside to inside?
5. **Attack crossings** — the highest-value bugs live at trust boundary crossings.

---

## Trust Map Schema

```markdown
| trustor | trustee | trust_type | strength | boundary_crossed |
|---------|---------|------------|----------|------------------|
| client | api | token_based | 0.7 | public→private |
| user | admin | header_based (X-Forwarded-For) | 0.9 | user→admin |
| app | webhook | signature_based | 0.5 | external→internal |
```

**High-impact bugs:** crossings over `no_auth`/`header_based`/`ip_based`/`internal_skip` edges.

---

## Finding Trust Violations

| Signal | What to Test |
|--------|--------------|
| ID parameter in URL | IDOR — can you access other users' data? |
| Auth header checked | Does the check actually exist? Or just assumed? |
| Webhook endpoint | Is the signature validated? Or just present? |
| Admin path | Is auth enforced? Or just hidden? |
| API versioning | Does v1 still work with weaker auth? |
| Error messages | Do they reveal trust assumptions? |

Next: [[Methodology]] → [[A→B Chains]]
