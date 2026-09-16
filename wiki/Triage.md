# Triage

Validate before submitting. The 7-Question Gate.

See also: [[BountyForge]], [[Lead Ledger]], [[Report Writing]], [[Vuln Classes]], [[Methodology]]

---

## The 7-Question Gate

Run on EVERY finding before writing a report:

| # | Question | Pass Criteria |
|---|----------|---------------|
| 1 | **Is the trigger proven?** | Path fires with a real request, not "could theoretically" |
| 2 | **Is the impact traced?** | Victim loses specific thing (amount, data, account) |
| 3 | **Is it reproducible?** | Others can follow your steps and get same result |
| 4 | **Is it not already known?** | Checked disclosed reports, CVE databases, duplicate reports |
| 5 | **Is it in scope?** | Program accepts this bug class |
| 6 | **Is there a real victim?** | Not self-XSS, not admin-only, not require unusual actions |
| 7 | **Is there business impact?** | Quantified: "N users", "$X at risk" |

**One wrong answer = KILL the finding.** Don't waste time.

---

## Always Rejected (Don't B submitting)

| Pattern | Kill Reason |
|---------|-------------|
| "Could theoretically allow..." | Trigger not proven |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless |
| Dead code with a bug in it | Not reachable |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |
| Self-XSS | No victim affected |
| Clickjacking on non-sensitive action | No meaningful impact |

---

## Severity Decision Guide

| Severity | Criteria |
|----------|----------|
| **Critical** | RCE, ATO, full financial control, chain that drains funds |
| **High** | IDOR on PII + write, SSRF to cloud metadata, SQLi with data exfil |
| **Medium** | IDOR on PII (read only), XSS with cookie theft, business logic flaw |
| **Low** | Self-XSS, info disclosure, version disclosure, missing headers |
| **Informational** | Best practice violations, defense-in-depth suggestions |

---

## CVSS 3.1 Quick Reference

```
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 (High)
AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N = 8.1 (High)
AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N = 6.3 (Medium)
AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N = 6.1 (Medium)
AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N = 3.7 (Low)
```

---

## Pre-Submit Checklist

- [ ] All 7 questions answered YES
- [ ] Title follows format: `[Bug Class] in [Endpoint] allows [role] to [impact]`
- [ ] First sentence says what attacker CAN DO (not "could potentially")
- [ ] HTTP requests are exact and reproducible
- [ ] Report is under 600 words
- [ ] CVSS score matches actual impact
- [ ] No "theoretical" language
- [ ] Checked for duplicates on program

Next: [[Report Writing]]
