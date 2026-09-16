# Lead Ledger

Open leads are persistent research objects, not notes to self.

See also: [[BountyForge]], [[Triage]], [[A→B Chains]], [[Methodology]], [[Trust Map]]

---

## Lead Lifecycle

```
OPEN → MUTATING → FINDING   (both halves proven → promoted)
  │         │
  │         └──→ PARKED (impact not provable → chain pool)
  └────────────→ PARKED (kill refused: only one half refuted)
  └──→ KILLED (BOTH halves refuted with evidence)
```

---

## The Two-Question Rule

Every lead has TWO independent questions:

| Question | What to answer |
|----------|----------------|
| **TRIGGER** — "Can this path fire?" | Reachable? Attacker-invokable? |
| **IMPACT** — "If it fires, what's the harm?" | Victim loses what? How much? |

**Rules:**
1. Both halves get a written trace.
2. Impact is victim-harm, not attacker-profit.
3. Three verdicts: FINDING / OPEN LEAD / KILL.
4. "Below the bar" is not a kill.

---

## One-Variable Mutation

Change exactly ONE thing per attempt:
- `user_id` (IDOR)
- `role` (privesc)
- `state` (TOCTOU)
- `amount` (business logic)
- `token` (auth bypass)
- `method` (GET vs POST)
- `version` (v1 vs v2)

**Never two at once.** You need to attribute the result.

---

## Missing Preconditions

Track them by name:
- "need second account for cross-account proof"
- "need race window (10ms sleep)"
- "need admin role"
- "need sibling endpoint /v2/users/{id}"
- "need chain partner for ATO"

Each resolves to: `missing → present | refuted | irrelevant` **with evidence**.

---

## Kill Guard

`kill_lead()` refuses unless BOTH halves are refuted with evidence.

One-half refutation = auto-park with counted dismissal attempt.

A parked lead stays in the chain pool. It becomes the missing half of a future A→B chain.

---

## Re-Trigger Conditions

Every KILLED or PARKED lead records what would reopen it:

| Dead End | Observable that Reopens |
|----------|------------------------|
| RAM escape | New shared-memory region appears |
| vsock channel | vsock device enumerated |
| MMDS metadata | 169.254.169.254 responds |
| Per-sandbox CA | CA cert differs between instances |

Next: [[Triage]] → [[Report Writing]]
