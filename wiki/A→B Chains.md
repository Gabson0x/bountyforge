# A→B Chains

Chain primitives. Two lows = one high.

See also: [[BountyForge]], [[Trust Map]], [[Triage]], [[Vuln Classes]], [[Lead Ledger]]

---

## The Principle

Single bugs pay. Chains pay 3-10x more. After every finding, hunt for a chain partner.

| Bug A | Bug B | Chain Impact |
|-------|-------|--------------|
| IDOR read | IDOR write | Full account control |
| SSRF | Cloud metadata | IAM creds → RCE |
| XSS | Cookie theft | Session hijack → ATO |
| Open redirect | OAuth redirect_uri | Token theft → ATO |
| GraphQL introspection | Missing field auth | Mass PII exfil |
| S3 listing | JS bundle secret | OAuth client_secret |
| Debug endpoint | Leaked env vars | Cloud credentials |
| CORS reflects origin | Credentialed request | Data theft |
| Rate limit bypass | OTP brute force | Account takeover |
| Host header injection | Password reset poisoning | ATO via reset link |

---

## Chain Protocol

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

---

## Known Chain Patterns

### Read → Write → ATO
```
IDOR read (GET /api/user/{id}) 
  → IDOR write (PUT /api/user/{id}) 
  → Email change + password reset 
  → Full account takeover
```

### SSRF → Internal → RCE
```
SSRF to internal service discovery
  → Find Redis/MongoDB/K8s API
  → Extract credentials
  → Execute commands
```

### XSS → CSRF → ATO
```
Stored XSS in profile
  → Force email change via XHR
  → Password reset to attacker email
  → Account takeover
```

### Open Redirect → OAuth → ATO
```
Open redirect in redirect_uri
  → OAuth code/token theft
  → Account linkage
  → Account takeover
```

---

## Finding Chain Partners

After finding bug A, ask:

1. **What does A give me access to?** (read, write, execute, impersonate)
2. **What other endpoints accept that access?** (siblings, related features)
3. **What's the next trust boundary I can cross?** (identity → authority → state)
4. **What's the cheapest escalation?** (one request vs multi-step)

---

## Quantifying Chain Impact

| Metric | Example |
|--------|---------|
| Users affected | "All 50K users with 2FA enabled" |
| Data exposed | "Email, phone, password hash for 10K accounts" |
| Financial impact | "$150K in fraudulent withdrawals possible" |
| Time window | "Attack works during password reset (5 min window)" |
| Prerequisites | "Requires 1 click from victim" (or "0 clicks") |

Next: [[Triage]] → [[Report Writing]]
