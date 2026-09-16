# Vuln Classes

Complete reference for bug classes. Hunt by class, not by endpoint.

See also: [[BountyForge]], [[Trust Map]], [[A→B Chains]], [[Web2 Recon]], [[Security Arsenal]]

---

## The Big 10 (Highest Pay)

### 1. IDOR / BOLA
**Trust violation:** Identity trust — system trusts user-supplied ID without verification.
**Test:** Change `user_id` in request. Access other users' data.
**Escalation:** IDOR read → IDOR write → ATO.
**Map:** [[Trust Map]] → Identity trust endpoints.

### 2. Auth Bypass
**Trust violation:** Identity trust — system trusts auth header without validation.
**Test:** Remove token, use expired token, use different user's token.
**Escalation:** Bypass auth → access admin → full control.
**Map:** [[Trust Map]] → Auth endpoints.

### 3. XSS (Reflected/Stored/DOM)
**Trust violation:** Input trust — system trusts user input in response without encoding.
**Test:** `<script>alert(1)</script>`, `<img onerror=alert(1)>`, event handlers.
**Escalation:** XSS → cookie theft → ATO.
**Map:** [[Trust Map]] → Input trust endpoints.

### 4. SSRF
**Trust violation:** Service trust — system trusts URL input without validation.
**Test:** `http://169.254.169.254/`, `http://localhost:6379/`, `file:///etc/passwd`.
**Escalation:** SSRF → cloud metadata → IAM creds → RCE.
**Map:** [[Trust Map]] → Service trust endpoints.

### 5. SQL Injection
**Trust violation:** Input trust — system trusts user input in SQL without parameterization.
**Test:** `' OR 1=1--`, `' UNION SELECT null,null--`, time-based blind.
**Escalation:** SQLi → data extraction → password hashes → ATO.
**Map:** [[Trust Map]] → Input trust endpoints.

### 6. Race Conditions
**Trust violation:** State trust — system trusts state without checking for concurrent modification.
**Test:** Parallel requests, double-spend, TOCTOU.
**Escalation:** Race → double-spend → financial loss.
**Map:** [[Trust Map]] → State trust endpoints.

### 7. Business Logic
**Trust violation:** Intent trust — system trusts user follows expected workflow.
**Test:** Skip steps, replay flows, manipulate amounts/quantities.
**Escalation:** Logic bypass → free items, negative balances, unauthorized actions.
**Map:** [[Trust Map]] → Intent trust endpoints.

### 8. Open Redirect
**Trust violation:** Input trust — system trusts redirect URL without validation.
**Test:** `?next=https://evil.com`, `?redirect=javascript:alert(1)`.
**Escalation:** Redirect → OAuth code theft → ATO.
**Map:** [[Trust Map]] → Input trust endpoints.

### 9. SSRF via Upload
**Trust violation:** Input trust — system trusts file content without validation.
**Test:** SVG with external entity, DOCX with XXE, image with SSRF payload.
**Escalation:** Upload → XXE → file read → RCE.
**Map:** [[Trust Map]] → Input trust endpoints.

### 10. Mass Assignment
**Trust violation:** Input trust — system trusts all user input as valid fields.
**Test:** Add `admin=true`, `role=superuser`, `balance=999999` to request body.
**Escalation:** Mass assign → privilege escalation → full control.
**Map:** [[Trust Map]] → Input trust endpoints.

---

## Bug Class → Trust Category

| Bug Class | Trust Category |
|-----------|----------------|
| IDOR, Auth Bypass, Session Hijack | Identity |
| XSS, SQLi, SSTI, XXE, File Upload | Input |
| Race, TOCTOU, Replay | State |
| SSRF, Webhook Bypass, Oracle Manipulation | Service |
| Business Logic, Workflow Skip | Intent |

---

## Testing by Trust Category

### Identity Trust
- Test without auth
- Test with different user's token
- Test with expired token
- Test with admin token on user endpoint
- Test horizontal access (user A → user B's data)
- Test vertical access (user → admin endpoint)

### Input Trust
- Test with special characters: `' " ` < > { } $ { }`
- Test with encoding: URL encode, double encode, Unicode
- Test with injection payloads: SQL, XSS, SSTI, XXE
- Test with oversized input
- Test with empty input

### State Trust
- Test with concurrent requests
- Test with replayed requests
- Test with modified state (pending → completed)
- Test with race conditions
- Test with double-spend

### Service Trust
- Test with internal URLs (169.254.169.254, localhost)
- Test with protocol smuggling (gopher://, file://)
- Test with DNS rebinding
- Test with signature bypass
- Test with replay attacks

### Intent Trust
- Test with skipped steps
- Test with manipulated amounts
- Test with negative values
- Test with unexpected order
- Test with edge cases (0, max, negative)

Next: [[Trust Map]] → [[Methodology]]
