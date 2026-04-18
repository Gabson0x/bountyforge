# Shared Agent Rules

These rules apply to ALL bug bounty hunter agents regardless of specialization.

## Output Format

Every finding must use this exact structure:

```
FINDING
  id: <sequential number>
  title: <≤10 words, impact-first>
  target: <contract name / endpoint / file path>
  location: <function name / line number / URL path>
  bug_class: <canonical class — see list below>
  group_key: <Target | location | bug_class>
  severity: critical | high | medium | low | informational
  confidence: <0–100>
  attack_path: <numbered steps — be concrete, quote exact code/params>
  impact: <who loses what, quantify if possible>
  poc: |
    <minimal working PoC — code, curl command, or step sequence>
  fix: <specific remediation — line-level where possible>
  agents: [<your agent name>]
```

For leads (incomplete paths):

```
LEAD
  id: <sequential>
  title: <≤10 words>
  target: <target>
  location: <location>
  bug_class: <class>
  group_key: <Target | location | bug_class>
  smell: <what looks wrong>
  unverified: <what you couldn't confirm>
  agents: [<your agent name>]
```

## Pre-Scan Kill List (Check BEFORE Deep Analysis)

Before producing ANY finding, run these five instant checks. If a finding
matches, do NOT analyze further — do not produce a FINDING or LEAD for it.
This saves tokens for real vulnerabilities.

### KILL-1: Operator Config as Attack Surface

If the "attack" requires controlling a CLI flag, config file, env var, or
deployment manifest — SKIP. Operator configuration is not attacker input.
This eliminates: "SSRF via config URL", "plaintext default in config",
"bind address 0.0.0.0 in default config", "no TLS on local connection."

**Test:** Does the dangerous value come from a user/request at runtime, or
from the operator's deploy-time configuration? If deploy-time → SKIP.

### KILL-2: Ecosystem-Standard Architecture

If every comparable implementation (2+ reference projects in the same
ecosystem) has the same "gap," it is a convention, not a vulnerability.

Common conventions that are NOT findings:
- Unauthenticated node operator RPC (Geth, CometBFT, Lighthouse, Reth)
- Plaintext local signer/HSM connection (Web3Signer, TMKMS)
- No CORS headers on node API (Axum/Actix default = browser-blocked)
- JWT without `exp` on Engine API (iat freshness is the real check)
- Version endpoint exposing git hash (all blockchain nodes)
- Mempool-only transaction filtering (standard EVM override pattern)

**Test:** Do Geth/Lighthouse/CometBFT/Reth do this same thing? If yes → SKIP.

### KILL-3: Test Suite Validates the "Vulnerable" Behavior

Before claiming a behavior is a bug, search the test files for assertions
that explicitly validate it as correct.

**Kill signals:**
- Test named `*_bypassed`, `*_allowed`, `*_skipped`
- Comments: `// Zero value bypasses X`, `// intentionally allowed`
- Test asserts the "vulnerable" result as expected/correct
- Test runs across multiple configurations or hardforks

**Test:** grep for `test.*<keyword>` and `<keyword>.*bypass` in test files.
If the team wrote tests asserting this behavior → SKIP.

### KILL-4: "Missing" Check Exists Elsewhere

When you think "check X is missing," trace the FULL validation path
including dependencies, middleware, and called functions before reporting.

**Common misses:** Check in dependency library (alloy, revm, OpenZeppelin),
check in middleware layer, check in different function called later,
implicit check (e.g., iat freshness makes exp redundant).

**Test:** Search the full call chain for validate/verify/check/enforce
functions related to the mechanism. If it exists elsewhere → SKIP.

### KILL-5: Standalone Hardening Suggestions

These are NEVER findings on their own:
- "Add rate limiting" (without an actual amplification attack)
- "Error messages include HTTP status codes" (not credentials/PII)
- "Default should be more secure" (dev convenience, not production)
- "Add defense-in-depth layer" (without showing the primary layer fails)
- "Use checked_sub instead of saturating_sub" (when check exists upstream)

---

## Canonical Bug Classes

**Smart Contract:** reentrancy, integer-overflow, integer-underflow, precision-loss, access-control-bypass, unprotected-initializer, storage-collision, front-running, oracle-manipulation, flash-loan-attack, signature-replay, cross-chain-replay, missing-zero-address-check, unchecked-return-value, denial-of-service, griefing, upgrade-bypass, delegatecall-injection, price-manipulation, invariant-violation, race-condition-sc, orphaned-role, emergency-misuse

**Web/API:** idor, broken-auth, jwt-bypass, ssrf, sqli, xss-stored, xss-reflected, xss-dom, xxe, rce, path-traversal, open-redirect, csrf, graphql-introspection, business-logic, race-condition-web, mass-assignment, insecure-deserialization, info-disclosure, cors-misconfiguration, account-takeover, privilege-escalation-web, api-key-exposure, oauth-bypass, subdomain-takeover, cache-poisoning, request-smuggling, host-header-injection

## Severity Calibration

| Severity | Smart Contract | Web/API | Infrastructure/Node |
|----------|---------------|---------|---------------------|
| Critical | Direct fund drain, >$1M at risk, protocol shutdown | RCE, full account takeover, mass data breach | Consensus safety violation (fork, double-sign), validator key compromise |
| High | Fund drain with preconditions, governance takeover, major invariant break | Auth bypass, IDOR on sensitive data, persistent XSS on admin | Compliance/sanctions bypass on regulated chain, consensus liveness attack |
| Medium | Partial fund loss, temporary DoS, privilege escalation | IDOR on non-sensitive data, SSRF to internal, self-XSS with escalation | DoS requiring validator access, partial enforcement bypass |
| Low | Griefing, dust loss, minor invariant, excess gas cost | Info disclosure, non-exploitable misconfig, low-impact logic flaw | Operational data disclosure, hardening gap with mitigating controls |
| Info | Best-practice deviation, no direct exploit | No security impact, hardening recommendation | Ecosystem-standard gap, config default suggestion |

## Behavior Rules

1. **Never assume intent.** Evaluate what the code/endpoint *allows*, not what it was *meant* to do.
2. **Quote exact code.** Every finding references the exact line, function name, or HTTP parameter responsible.
3. **Trace complete paths.** If you cannot trace from entry to impact, output a LEAD, not a FINDING.
4. **No duplicate speculation.** If another agent's domain clearly owns a finding class, do not re-report it. Flag it as cross-domain if it connects to your area.
5. **Composite chains.** If your finding's output enables a higher-severity impact by combining with another class, note `chain_with: <bug_class>`.
6. **Platform awareness.** If a target platform is specified, calibrate severity to that program's known policies (e.g., Immunefi critical = >$1M protocol funds; HackerOne/Bugcrowd varies by program).
7. **No invented facts.** If a variable, endpoint, or behavior isn't visible in the source, say "not visible in scope" rather than assuming.
