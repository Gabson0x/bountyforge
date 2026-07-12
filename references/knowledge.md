# Knowledge — Learning from Disclosed Reports

The highest-ROI pre-hunt activity is reading what other hackers already found and got paid for. This reference teaches the agent how to search for, extract patterns from, and apply lessons from disclosed bug bounty reports.

---

## Why This Matters

Disclosed reports are a cheat code. They tell you:
- Exactly which endpoints were vulnerable
- Exactly what the missing check was
- Exactly how much the program paid
- What the fix looks like (via commit diffs)

A hunter who reads 10 disclosed reports before hunting finds 3-5x more bugs than one who starts blind.

---

## Report Sources (in priority order)

### 1. HackerOne Hacktivity (Primary)

```
https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+IDOR
https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+SSRF
https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+XSS
https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+auth+bypass
```

Filter for: disclosed=true, bounty awarded, sorted by trending or newest.

### 2. HackerOne GraphQL API

```bash
# Search hacktivity for a specific program
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      hacktivity_items(
        first: 25,
        order_by: {field: popular, direction: DESC},
        where: {
          team: {handle: {_eq: \"PROGRAM_HANDLE\"}},
          report: {disclosure_state: {_eq: \"disclosed\"}}
        }
      ) {
        nodes {
          ... on HacktivityDocument {
            report {
              title
              severity_rating
              bounty_awarded
              vulnerability_information
            }
          }
        }
      }
    }"
  }' | jq '.data.hacktivity_items.nodes[].report'
```

### 3. Bugcrowd Crowdstream

```
https://bugcrowd.com/PROGRAM_NAME/crowdstream
```

Public disclosures appear in the program's Crowdstream. Filter by severity and date.

### 4. Intigriti Public Reports

```
https://www.intigriti.com/programs
```

Some programs publish anonymized findings. Check the program page for a "disclosed reports" section.

### 5. Google Dorks for Writeups

```
site:medium.com "PROGRAM_NAME" "bug bounty"
site:infosecwriteups.com "PROGRAM_NAME"
site:hackerone.com/reports "PROGRAM_NAME"
"PROGRAM_NAME" "IDOR" "bounty" site:medium.com
github.com "PROGRAM_NAME" "vulnerability" "fix"
```

### 6. Solodit (Web3/Smart Contracts)

```
https://solodit.cyfrin.io
```

50,000+ searchable audit findings. Search by protocol name, vulnerability class, or code pattern.

---

## The "What Changed" Method (Highest ROI Pattern)

This is the single most effective way to use disclosed reports:

```
1. Find a disclosed report for the SAME tech stack as your target
   (e.g., if your target uses Django REST Framework, find DRF IDOR reports)

2. Find the fix commit → Read the diff
   (search GitHub for "fix IDOR" in a DRF project)

3. Identify the anti-pattern in the vulnerable code
   (e.g., "get_object_or_404 without checking request.user owns the object")

4. Grep your target's source code for that SAME anti-pattern
   (grep -rn "get_object_or_404" --include="*.py")

5. Test every match
```

This works because developers across different companies make the SAME mistakes with the SAME frameworks.

---

## 6 Universal Patterns from Top Reports

These patterns appear across ALL programs, ALL tech stacks, ALL bug classes:

### Pattern 1: Feature Complexity = Bug Surface

Every new feature adds bugs. Focus on:
- Import/export functionality (SSRF, XSS, code execution)
- Multi-step workflows (state confusion, race conditions)
- Integration with third-party services (OAuth misconfigs, SSRF)
- Batch/bulk operations (IDOR, rate limit bypass)

### Pattern 2: Developer Inconsistency = Strongest Evidence

Look for the SAME operation implemented TWO different ways:
- `timingSafeEqual()` in auth module but `===` in password reset
- Auth check middleware on `/api/v2/` but not on `/api/v1/`
- Input validation in the web UI but not in the mobile API
- CORS headers set correctly on one endpoint but wildcard on another

### Pattern 3: The "Else Branch" Bug

Proxy/gateway code that handles the "main path" correctly but has a dangerous fallthrough:
- "If the token is valid, proceed. Else... just pass the request through?"
- "If the role is admin, grant access. Else... grant basic access instead of denying?"
- "If the file extension is in the allowlist, serve it. Else... serve it anyway with a different content-type?"

### Pattern 4: Import/Export = SSRF

Historically, EVERY "import from URL" feature has had SSRF at some point:
- Image import (`?url=https://...`)
- Document import (PDF generation, office document preview)
- Data import (CSV/JSON from URL)
- Webhook registration (the registration itself is SSRF)
- Link unfurling/preview (Slack, Discord, any chat feature)

### Pattern 5: Secondary/Legacy Endpoints = No Auth

- `/api/v2/users/123` — auth checked
- `/api/v1/users/123` — auth NOT checked
- `/internal/users/123` — auth NOT checked
- `/api/users/123?format=csv` — auth NOT checked (export path)
- GraphQL field `user(id: 123)` — field-level auth missing

### Pattern 6: Race Windows in Financial Operations

Any operation that is "check, then act" is racy:
- Check balance → deduct = double-spend
- Check coupon validity → mark used = multi-redeem
- Check invite limit → create invite = unlimited invites
- Check rate limit counter → increment = race past limit

---

## Program-Specific Intel Gathering

### Before Hunting a Program, Answer These:

```
1. What's the average bounty? (signals program generosity)
   → Check hacktivity: sort by bounty amount

2. What bug classes get paid MOST?
   → Count disclosed reports by type: IDOR wins? SSRF? XSS?

3. What severity floor do they pay?
   → Do they pay for Medium? Only High+?

4. What's their tech stack?
   → Check job postings, engineering blog, HTTP headers, JS bundles

5. Who are the top 3 hackers on this program?
   → Check hacktivity leaderboard — read ALL their disclosed reports

6. What's the most recent disclosed report?
   → What was the bug? When was it fixed? The anti-pattern might still exist elsewhere.
```

---

## Learning from Report Metadata

When reading a disclosed report, extract these data points:

```markdown
| Field | Value |
|-------|-------|
| Report ID | #123456 |
| Title | [Bug class] in [endpoint] allows [impact] |
| Bounty | $X,XXX |
| Severity | High/Critical |
| Bug Class | IDOR / SSRF / XSS / etc. |
| Endpoint Pattern | /api/v1/resource/{id} |
| Missing Check | No ownership verification on GET |
| Fix Pattern | Added `if (resource.owner !== request.user) return 403` |
| Key Insight | The `get_object_or_404` helper doesn't check ownership |
```

Store these as you read reports. After 10 reports, patterns emerge.

---

## Pattern Extraction Prompt

When you find a disclosed report, ask yourself:

1. **What was the vulnerable endpoint pattern?**
   → `/api/v1/users/{id}/profile` — note the exact path structure

2. **What check was MISSING?**
   → "The code checked that the user was authenticated but NOT that user.id === requested_id"

3. **What told the hacker to look there?**
   → "They noticed user IDs in API responses and tried swapping them"

4. **What was the fix?**
   → "Added ownership check: `if (requested_user.org_id !== request.user.org_id) reject`"

5. **Can I generalize this pattern?**
   → "Any endpoint with a user-controlled ID in the URL that doesn't verify org membership"

---

## Anti-Pattern Library (Build Over Time)

As you read disclosed reports, build a personal library of anti-patterns:

```markdown
## Django REST Framework
- `get_object_or_404(Model, pk=id)` without ownership check → IDOR
- `serializer.save(owner=request.user)` but owner field is NOT read-only → mass assignment
- `@permission_classes([IsAuthenticated])` but no object-level permission → IDOR

## Express.js
- `req.params.id` used directly in DB query without ownership check → IDOR
- `req.body.role` accepted in user update endpoint → privilege escalation
- `app.use(cors({origin: true}))` → credentials-enabled CORS from any origin

## Laravel
- `User::find($id)` without `where('team_id', auth()->user()->team_id)` → cross-tenant IDOR
- `$request->except(['is_admin'])` → can be bypassed with array notation
- Route model binding without policy → IDOR on every bound model

## GraphQL (any framework)
- `node(id: $id)` resolver without type-specific auth → cross-type data access
- Missing `@auth` directive on sensitive fields → field-level IDOR
- Introspection left enabled → full schema enumeration

## GitHub Actions
- `${{ github.event.issue.title }}` in `run:` block → RCE via expression injection
- `pull_request_target` + `actions/checkout` without `ref` → untrusted code execution
- `secrets: inherit` in reusable workflow → secret leakage to called workflow
```

---

## Pre-Hunt Knowledge Pipeline (Run This Every Time)

```bash
#!/bin/bash
# knowledge-pipeline.sh — run before hunting a program
# Usage: bash knowledge-pipeline.sh PROGRAM_HANDLE

PROGRAM="$1"

echo "=== Knowledge Pipeline: $PROGRAM ==="
echo ""

# 1. Fetch recent disclosed reports from HackerOne Hacktivity
echo "[1/4] Fetching disclosed reports..."
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{ hacktivity_items(first:10, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\\\"$PROGRAM\\\"}}, report:{disclosure_state:{_eq:\\\"disclosed\\\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating bounty_awarded } } } } }\"}" \
  | jq -r '.data.hacktivity_items.nodes[].report | "  [\(.severity_rating)] \(.title) — $\(.bounty_awarded)"'

echo ""

# 2. Search for public writeups
echo "[2/4] Searching for public writeups..."
echo "  Check: https://medium.com/search?q=$PROGRAM%20bug%20bounty"
echo "  Check: https://infosecwriteups.com/search?q=$PROGRAM"

# 3. Check GitHub for recent security fixes
echo "[3/4] Searching GitHub for security fixes..."
curl -s "https://api.github.com/search/issues?q=${PROGRAM}+security+fix+in:title&sort=updated&order=desc&per_page=5" \
  | jq -r '.items[] | "  \(.title) — \(.html_url)"' 2>/dev/null

echo ""

# 4. Summarize
echo "[4/4] Knowledge pipeline complete."
echo "  → Top bug class from disclosed reports: _____"
echo "  → Average bounty: $_____"
echo "  → Most recent disclosure date: _____"
echo "  → Key anti-pattern to grep for: _____"
```

---

## Integrating Knowledge into the Hunt

### At Session Start

1. Run the knowledge pipeline for the target program
2. Read the 5 most recent disclosed reports
3. Extract the anti-pattern from each
4. Build a checklist: "these are the mistakes this team makes"

### During the Hunt

1. When you find a lead, compare against disclosed reports: "has this endpoint pattern been reported before?"
2. When you find a bug, check: "is there a sibling endpoint with the same anti-pattern?"
3. The "What Changed" method: for every fix you find, grep the codebase for the vulnerable pattern

### When Writing the Report

1. Reference similar disclosed reports to calibrate severity
2. If a similar bug was paid $X,000, mention it in your impact statement
3. If the same anti-pattern was found and fixed elsewhere, note that

---

## Knowledge Decay

Report data ages. Prioritize fresh reports:
- Last 6 months: HIGH priority — likely still relevant
- 6-12 months: MEDIUM priority — check if the fix was comprehensive
- 12+ months: LOW priority — program may have changed significantly

---

## Ethical Note

Disclosed reports are PUBLIC information. Using them to learn patterns is legitimate research. However:
- Do NOT copy-paste someone else's PoC and submit it
- Do NOT re-test the exact same endpoint that was already fixed (wastes triager time)
- DO use the PATTERN to find DIFFERENT vulnerable endpoints
- DO cite disclosed reports when relevant ("similar to report #123456, the same anti-pattern exists in...")
