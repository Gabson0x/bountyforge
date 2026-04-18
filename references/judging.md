# Finding Gate Evaluation (Judging)

Every deduplicated finding passes five sequential gates. Fail any gate → **REJECTED** or **DEMOTED** to LEAD. Later gates are not evaluated for failed findings.

---

## Gate 0 — Instant Kill (Pre-Filter)

Before any deep analysis, apply these binary checks. These catch the
highest-volume false positives from automated scanning.

### 0a. Operator-Controlled Input

If the attack path starts with "attacker controls config / CLI / env var /
deployment manifest" → **REJECTED**. Operator configuration is not attacker
input. If the attacker controls the server config, they already own the
system.

### 0b. Ecosystem Convention

If the reported "gap" matches standard architecture across 2+ reference
implementations in the same ecosystem → **REJECTED**.

Reference check (pick the matching ecosystem):
- **EVM nodes:** Geth, Reth, Besu, Nethermind
- **CL clients:** Lighthouse, Prysm, Teku, Nimbus
- **Cosmos/CometBFT:** CometBFT, Osmosis, Cosmos Hub
- **Smart contracts:** OpenZeppelin, Solmate
- **Web/API:** OWASP baseline for the framework

Common ecosystem conventions (always reject):
- Unauthenticated node operator RPC
- Plaintext local infrastructure communication (signer, CL↔EL)
- Version/health endpoints without auth
- No CORS headers on non-browser APIs
- JWT without `exp` when `iat` freshness is enforced

### 0c. Test-Suite Validated Behavior

If the target codebase's test suite contains test cases that explicitly
assert the "vulnerable" behavior as correct → **REJECTED**.

Signals: test names containing `_bypassed` / `_allowed` / `_skipped`,
comments like "Zero value bypasses X", test expectations asserting the
behavior across multiple configurations.

### 0d. Check Exists in Call Chain

If the finding claims "check X is missing" but the check exists in a
dependency, middleware layer, or called function → **REJECTED**.

Trace the full validation path before accepting "missing check" findings.

### 0e. Standalone Hardening

If the finding is purely "add rate limiting", "use stricter defaults",
"add defense-in-depth", or "improve error messages" without demonstrating
that the primary security control fails → **REJECTED**.

---

## Gate 1 — Refutation

Construct the strongest argument that the finding is wrong. Find the guard, check, or constraint that kills the attack — quote the exact line and trace how it blocks the claimed step.

- **Concrete refutation** (a specific guard blocks the exact claimed step) → **REJECTED** (or **DEMOTE** if a code smell remains worth investigating)
- **Speculative refutation** ("probably wouldn't happen", "likely intended") → **clears**, continue to Gate 2

---

## Gate 2 — Reachability

Prove the vulnerable state exists in a live/deployed system.

- **Structurally impossible** (enforced invariant in code prevents the state from ever occurring) → **REJECTED**
- **Requires privileged actions outside normal operation** (owner must misconfigure, multi-sig must collude) → **DEMOTE**
- **Achievable through normal usage, fee-on-transfer tokens, rebasing, common admin actions** → **clears**, continue to Gate 3

---

## Gate 3 — Trigger

Prove an unprivileged (or minimally privileged) actor can execute the attack profitably.

- **Only a trusted role can trigger** → **DEMOTE** (report as medium/low, not critical)
- **Costs exceed extraction** (attack costs more in gas/capital than it gains) → **REJECTED**
- **Unprivileged actor can trigger profitably** → **clears**, continue to Gate 4

---

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- **Self-harm only** (attacker loses their own funds, no other victim) → **REJECTED**
- **Dust-level, non-compounding, no cascade** → **DEMOTE** to low/informational
- **Material loss to identifiable victim** (user funds drained, protocol shutdown, data breached) → **CONFIRMED**

---

## Severity Adjustment After Gates

After all five gates clear, adjust severity downward if:
- Attack requires specific timing (e.g., within 1 block window): **-1 severity level**
- Attack requires non-trivial capital (>$100K flash loan for medium-value target): **-1 severity level**
- Impact is bounded (attacker can profit but not drain the entire pool): **-1 severity level**
- Fix is already deployed on mainnet but not in the reviewed commit: **DEMOTE** + note

---

## LEAD Promotion Before Finalization

Before finalizing the LEAD list, promote where warranted:

1. **Cross-contract echo:** Same root cause confirmed as FINDING in Contract A → promote in Contract B where identical pattern appears (confidence 75).
2. **Multi-agent convergence:** 2+ agents flagged the same area, finding was demoted (not rejected) → promote to FINDING at confidence 75.
3. **Partial path completion:** Only weakness is an incomplete trace, but path is reachable and unguarded → promote to FINDING at confidence 75, no fix required.
4. **Web cross-feature:** Confirmed auth bypass in endpoint A enables IDOR in endpoint B → chain them and promote.
5. **Internal asymmetry (highest signal):** Component A has security control X at layer Y, but Component B (same purpose, same codebase) lacks it. This is the strongest finding pattern — the team's own code proves the control is necessary, so its absence is an oversight, not a design choice. Promote to FINDING at confidence 85+. Example: blocklist enforced at execution layer but denylist only at mempool → the denylist is bypassable by block proposers.

---

## Do Not Report

- Linter warnings, compiler suggestions, gas micro-optimizations.
- Missing NatSpec or event emissions.
- Centralization risk without an exploit path.
- Admin privileges functioning as designed (unless the design itself is the vulnerability).
- Implausible preconditions that require the protocol to already be compromised.
- Self-XSS without any escalation path.
- Logout CSRF without session fixation.
- Rate limiting that genuinely prevents exploitation in the defined threat model.
