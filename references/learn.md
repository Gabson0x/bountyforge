# Phase 2 Learn — Disclosed Reports, Threat Model, Notes

> Split from SKILL.md v4.1.0. Load before hunting a new program. Full pipeline: `references/knowledge.md`.

---

# PHASE 2: LEARN (Pre-Hunt Intelligence)

## Disclosed Report Pipeline (knowledge.md)

At hunt start, ALWAYS check for disclosed reports on the target program:

```bash
# HackerOne Hacktivity for program
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

### "What Changed" Method (Highest ROI)
1. Find disclosed report for similar tech → Get the fix commit → Read the diff → Identify the anti-pattern → Grep your target for that same anti-pattern

### 6 Key Patterns from Top Reports
1. **Feature Complexity = Bug Surface** — imports, integrations, multi-tenancy, multi-step workflows
2. **Developer Inconsistency = Strongest Evidence** — `timingSafeEqual` in one place, `===` elsewhere
3. **"Else Branch" Bug** — proxy/gateway passes raw token without validation in else path
4. **Import/Export = SSRF** — every "import from URL" feature has historically had SSRF
5. **Secondary/Legacy Endpoints = No Auth** — `/api/v1/` guarded but `/api/` isn't
6. **Race Windows in Financial Ops** — check-then-deduct as two DB operations = double-spend

## Threat Model Template
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

---

