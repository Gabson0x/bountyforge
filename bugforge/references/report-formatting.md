# Report Formatting Guide

Format the final output based on the target platform. Default to Generic if no platform is specified.

---

## Generic / Internal Format

```markdown
# Bug Bounty Audit Report
**Target:** {target name}
**Date:** {date}
**Auditor:** {auditor handle}
**Scope:** {files / domains / contracts reviewed}

---

## Executive Summary

{1–3 sentences: what was reviewed, highest severity found, total findings count}

| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Informational | N |
| **Total** | **N** |

---

## Findings

### [SEVERITY-N] {Title}

**Severity:** Critical / High / Medium / Low / Informational
**Confidence:** {0–100}
**Target:** {contract / endpoint / file}
**Location:** {function / line / URL}
**Bug Class:** {canonical class}
{if --cvss: **CVSS 3.1:** {vector string} → {score}}

#### Description

{2–4 sentences explaining the vulnerability. What is the code/system doing wrong? Why does this matter?}

#### Attack Path

1. {Step 1}
2. {Step 2}
3. {Step N — attacker achieves impact}

#### Proof of Concept

```{language}
{minimal PoC — code, transaction sequence, or curl command}
```

#### Impact

{Who is the victim? What do they lose? Quantify if possible.}

#### Recommended Fix

{Specific, actionable remediation. Reference exact line or function.}

---
```

---

## HackerOne Format

```markdown
## Summary

{1–2 sentences: what the bug is and why it matters. No jargon in the first sentence.}

## Vulnerability Details

**Vulnerability Type:** {CWE or canonical class}
**Severity:** {Critical | High | Medium | Low | None}
**CVSS Score:** {score} — `{CVSS:3.1/AV:N/AC:L/...}`

**Affected Asset:** {URL, contract address, or file path}
**Affected Component:** {function name, endpoint, or module}

## Steps to Reproduce

1. {Navigate to / Call / Send}
2. {Observe / Confirm}
3. {Achieve impact}

## Proof of Concept

{Include: code snippet, screenshot description, curl command, or transaction hash}

## Impact

{Describe the worst-case impact. Who is affected? What data or funds are at risk?}

## Supporting Material

{Optional: logs, diff, references to similar CVEs, relevant code snippets}
```

---

## Bugcrowd Format

```markdown
**Title:** {Title — Impact First}

**VRT Category:** {Bugcrowd VRT category, e.g., "Server-Side Injection > SQL Injection"}
**Priority:** P1 / P2 / P3 / P4 / P5

**Asset:** {target URL or contract}

**Description:**
{Clear explanation of the vulnerability without assuming deep technical knowledge from the triage team.}

**Steps to Reproduce:**
1. ...
2. ...
3. ...

**Expected Result:** {What a secure system would do}
**Actual Result:** {What the vulnerable system does}

**Proof of Concept:**
{Attach or embed PoC}

**Impact:**
{Describe attacker capability and victim harm}

**CVSS Vector:** `{vector}` ({score})

**Remediation Suggestion:**
{Fix recommendation}
```

---

## Intigriti Format

```markdown
**Title:** {Title}
**Severity:** Critical / High / Medium / Low / Best Practice

**Affected URL / Asset:** {target}

**Description:**
{Explain the vulnerability clearly. Intigriti triagers appreciate context on why the vulnerability is dangerous.}

**Reproduction Steps:**
1. ...
2. ...
3. ...

**Proof of Concept:**
{Link, screenshot, code, or curl}

**Impact:**
{Concrete impact statement}

**CVSS 3.1:** `{vector}` → {score}

**Suggested Fix:**
{Remediation}
```

---

## Immunefi Format

```markdown
**Vulnerability Title:** {Title}

**Severity:** Critical / High / Medium / Low

**Type:** {Smart Contract Bug / Website/App Bug / Blockchain/DLT Bug}
**Vulnerability Classification:** {Immunefi classification — e.g., "Manipulation of governance voting result", "Direct theft of any user funds"}

**Blockchain/Tech Stack:** {Ethereum / Aptos / Solana / TRON / etc.}
**Smart Contract Address:** {if applicable}
**Protocol Name:** {target protocol}

**Description:**
{Detailed technical description. Immunefi reviewers are technical — be specific. Reference exact functions, storage slots, and call sequences.}

**Attack Scenario:**

{Narrative description of a realistic attack from attacker setup to impact}

**Proof of Concept:**
```{language}
{PoC code — Foundry test preferred for EVM, Move script for Aptos}
```

**Impact:**
{Quantify: how much could be drained? Which assets? Which users?}

**Recommended Fix:**
{Specific, implementable fix with code diff if possible}

**References:**
{Prior audits, similar bugs, relevant EIPs or standards}
```

---

## Formatting Rules (All Platforms)

1. **Title format:** `[Severity] Action-oriented title describing the impact` — e.g., `[Critical] Attester Key Compromise Enables Unlimited USDC Minting`
2. **No vague impact:** "attacker can do bad things" is not acceptable. Specify: drained funds, stolen credentials, bypassed auth.
3. **PoC must be runnable** (or clearly executable with the described steps). Do not describe a PoC without providing it.
4. **CVSS required** for Immunefi always, for HackerOne/Bugcrowd/Intigriti when `--cvss` flag is set.
5. **Severity self-consistency:** CVSS score and severity label must agree (Critical = 9.0–10.0, High = 7.0–8.9, Medium = 4.0–6.9, Low = 0.1–3.9).
6. **One finding per report** when generating submission-ready reports. If multiple findings exist, generate separate report blocks clearly delineated.
