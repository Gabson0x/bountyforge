# Report Writing

Platform-specific templates, human tone, impact-first.

See also: [[BountyForge]], [[Triage]], [[Lead Ledger]], [[A→B Chains]], [[Methodology]]

---

## Report Format

### Title
`[Bug Class] in [Endpoint] allows [role] to [impact]`

**Examples:**
- `IDOR in /api/v2/users/{id} allows any user to read other users' PII`
- `SSRF in webhook handler allows attacker to access cloud metadata`
- `Race condition in withdrawal allows double-spend of $5,000`

### Summary (1 sentence)
What the attacker CAN DO. Not "could potentially" — what they ACTUALLY DO.

**Good:** "An attacker can read any user's profile data including email, phone, and password hash by changing the user_id parameter in GET /api/v2/users/{id}."

**Bad:** "An attacker could potentially access other users' data if certain conditions are met."

### Steps to Reproduce
Exact HTTP requests. Copy-pasteable. Include:
- Full URL
- All headers (especially auth)
- Request body
- Expected response

### Impact
Quantified business impact:
- "All 50K users affected"
- "$150K in fraudulent withdrawals possible"
- "Password hashes exposed for 10K accounts"

### CVSS Score
CVSS 3.1 vector that MATCHES actual impact. See [[Triage]].

---

## Platform Formats

### HackerOne
```markdown
## Summary
[1 sentence: what attacker CAN DO]

## Vulnerability Type
[URL to CWE]

## Vulnerable Endpoint
[URL]

## Vulnerable Parameter
[param name]

## Attack Vector
[exact HTTP request]

## Impact
[quantified business impact]

##CVSS
[CVSS 3.1 vector]
```

### Bugcrowd
```markdown
## Summary
[1 sentence]

## Vulnerability Details
[description]

## Steps to Reproduce
[1. 2. 3.]

## Impact
[quantified]

## Supporting Material
[screenshots, videos]
```

### Immunefi
```markdown
## Summary
[1 sentence]

## Asset
[contract address]

## Vulnerability Details
[technical description]

## Impact
[financial impact, not just "could be exploited"]

## Code Snippet
[solidity code]

## Recommendation
[fix suggestion]
```

---

## Human Tone Rules

- **Be direct.** "An attacker can..." not "It might be possible to..."
- **Be specific.** "Reads email, phone, password hash" not "accesses user data"
- **Be quantified.** "50K users affected" not "many users"
- **Be reproducible.** Exact HTTP requests, not vague descriptions
- **Be honest.** If impact is Medium, say Medium. Don't inflate.

---

## Severity Escalation Language

| Severity | Language |
|----------|----------|
| Critical | "allows full account takeover", "enables theft of $X", "results in RCE" |
| High | "exposes sensitive PII for N users", "bypasses authentication" |
| Medium | "allows unauthorized access to", "could be chained with" |
| Low | "reveals internal information", "missing security header" |

---

## Pre-Submit Checklist

- [ ] Title follows format
- [ ] First sentence is impact-first
- [ ] HTTP requests are exact
- [ ] Under 600 words
- [ ] CVSS matches impact
- [ ] No "theoretical" language
- [ ] Checked for duplicates
- [ ] In scope for program

See [[Triage]] for the 7-Question Gate.
