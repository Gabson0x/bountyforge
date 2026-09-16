---
name: bb-methodology
description: The "3rd eye" for pentesting — reminds agent to understand before assuming, validate before reporting.
---

# 3rd Eye — Pentesting Reminder

You are a pentesting reminder system. Your job is to catch mistakes.

See also: [[BountyForge]], [[Methodology]], [[Triage]], [[Trust Map]], [[Vuln Classes]], [[A→B Chains]], [[Lead Ledger]], [[Report Writing]], [[Wild Mode]]

---

## BEFORE YOU START

1. **Read the program page.** All rules. Safe harbor. Scope. What pays.
2. **Read last 10 disclosed reports.** What got paid? What didn't? Patterns.
3. **Understand the tech stack.** Framework? Version? Auth model?
4. **Create temp emails.** You need 2-3 for multi-account testing. See [[Web2 Recon]].
5. **Define your goal.** "Today I target [X] to achieve [C/I/A/ATO/RCE]"

---

## THE TRUST-FIRST LOOP

```
MAP → OBSERVE → MODEL → HYPOTHESIZE → RANK → TEST → INTERPRET
→ NEW HYPOTHESES → CHAIN → VALIDATE → KILL/ESCALATE/REPORT
```

**Map trust first.** Every bug is a trust violation. See [[Trust Map]].

**Hypothesize from trust.** "What if this trust is misplaced?" Name the violation.

**Rank by information gain.** Test what teaches you most, even if it fails.

**Test minimally first.** One request, one change. Signal before proof.

**Interpret everything.** A "no" teaches you about the system. Update your model.

**Chain relentlessly.** Two lows = one high. See [[A→B Chains]].

---

## THE TWO-QUESTION RULE

Every finding has TWO independent questions. Answer BOTH:

| Question | What to answer |
|----------|----------------|
| **TRIGGER** — "Can this path fire?" | Reachable? Attacker-invokable? Not trusted-actor-only? |
| **IMPACT** — "If it fires, what's the harm?" | Victim loses what? How much? Permanently or recoverable? |

**Rules:**
1. Both halves get a written trace. Answering one and assuming the other is a process error.
2. Impact is victim-harm, not attacker-profit.
3. Three verdicts only: FINDING / OPEN LEAD / KILL. See [[Lead Ledger]].
4. "Below the bar" is not a kill.
5. Severity estimation never precedes the impact trace.

---

## 3RD EYE CHECKLIST

### DON'T ASSUME
- [ ] Did I actually test this, or am I assuming it's blocked?
- [ ] Did I try different methods, headers, versions?
- [ ] Did I test without auth before assuming auth is required?
- [ ] Did I try the bypass before assuming the WAF blocks it?

### UNDERSTAND BEFORE EXPLOITING
- [ ] Do I know what framework/stack this uses?
- [ ] Do I know how auth works here?
- [ ] Have I read the disclosed reports for this program?
- [ ] Do I understand what the developer believed when building this?

### VALIDATE BEFORE REPORTING
- [ ] **Trigger proven?** Not "could theoretically" — actually fires.
- [ ] **Impact traced?** Not "might lead to" — victim loses specific thing.
- [ ] **Reproducible?** Others can follow my steps.
- [ ] **Not already known?** Checked disclosed reports and CVEs.
- [ ] **In scope?** Program accepts this bug class.
- [ ] **Real victim?** Not self-XSS, not admin-only, not unusual actions.
- [ ] **Business impact?** Quantified: "N users", "$X at risk".

**One wrong answer = kill the finding.** See [[Triage]].

### REPORT WITH WORDING
- Title: `[Bug Class] in [Endpoint] allows [role] to [impact]`
- First sentence: what the attacker CAN DO (not "could potentially")
- Exact HTTP requests in steps to reproduce
- Under 600 words
- CVSS 3.1 that MATCHES actual impact
- No "theoretical" language — prove it or drop it

See [[Report Writing]].

---

## WHEN STUCK

| Stuck because... | Do this |
|------------------|---------|
| Can't find subdomains | Try different sources, Google Dorks. See [[Web2 Recon]] |
| Found subdomain, don't know what to test | Map it first. See [[Trust Map]] |
| Testing but nothing works | Switch vuln class (20-min rule). See [[Vuln Classes]] |
| Found bug, impact is low | Chain it. See [[A→B Chains]] |
| WAF blocks payload | Bypass techniques, then rotate |
| Been stuck 45 min on one param | STOP. Rabbit hole. Move on. |
| New endpoint discovered | Map it first, then attack. See [[Trust Map]] |
| Need payloads or bypasses | See [[Security Arsenal]] |
| Writing report | See [[Report Writing]], [[Triage]] |
| Smart contract audit | See [[Web3 Audit]], [[Smart Contract Audit]] |
