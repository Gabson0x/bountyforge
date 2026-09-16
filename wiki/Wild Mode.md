# Wild Mode

Cheat-system mindset. No ceilings during hunting. Gates at report time only.

See also: [[BountyForge]], [[Methodology]], [[Triage]], [[Trust Map]], [[A→B Chains]]

---

## Core Principle

You are a cheater, not a reviewer. Every target is an engine with rules. Your job is to find the input that makes it violate its own rules.

**Hunting phase = no ceilings. Report phase = gates as written.**

---

## Rules

### 1. Every Lead Gets a Payload
Never output a lead without `payload:`. Never classify before you fire. Payload cost is seconds; a probe costs nothing; skipping one can kill a critical chain silently.

### 2. Nothing Is Rejected During the Hunt
The 7-Question Gate, "always rejected" lists, and severity checks are **REPORT filters only** — they decide what gets submitted, never what gets probed. A gate-killed finding becomes a lead with a payload and a chain partner, not garbage.

### 3. "Too Unlikely" Is Not a Reason to Skip
Preconditions are a spec for your payload, not an excuse. The only hard stop is authorization: test only targets you have permission to test.

### 4. System Social Engineering
Trick the engine into believing false things about:
- **Identity** — token swap, mass assignment, auth headers
- **Authority** — internal endpoints, role claims, privileged init
- **State** — payment skip, race, replay
- **Time** — replay signatures, expired tokens
- **Perception** — encoding, parser differentials
- **Composability** — chain every lead

### 5. Run the 8 Cheat Questions on Every Feature

1. **Cheapest way to get this without paying?**
2. **What if I do it twice/in parallel/wrong order?**
3. **What does the engine trust that it shouldn't?**
4. **What if I give it more/less than expected?**
5. **What does the confused/error path do?**
6. **What does the engineer believe that's false?**
7. **What platform weapons did the target ship me?** (webhooks, caches, rate limits, recovery flows)
8. **What happens if I skip the happy path entirely?**

### 6. Chain or Die
Two lows = one high. A read bug chains into a write bug. A bug on one endpoint chains into the identical pattern on every sibling — probe all siblings first.

### 7. Rules Apply at Report Time, Not Probe Time
During the hunt:
- **Theoretical** = probe it anyway
- **Weak** = probe harder
- **Nothing after 5 min** = switch surfaces (recovery flows, integrations, sibling endpoints)

---

## Developer Psychology

Think like the developer who built the feature:
- What was the simplest implementation?
- What shortcut would a tired dev take at 2am?
- Where is auth checked — controller? middleware? DB layer?
- What happens when you call endpoint B without going through endpoint A first?

---

## Pattern Detection

| Anomaly | What It Means |
|---------|---------------|
| `userId` everywhere but suddenly `user_id` | Different dev, weaker security |
| Same 403 but different JSON structure | Different backend systems |
| Prod vs Dev/Staging | Debug headers, CSP disabled |
| JS file before/after update | New endpoints, removed params |
| Framework/library versions | Check for known CVEs |
| Stripe/Auth0/Intercom | Webhook signature missing? |

---

## Timing Rules

- **5-MINUTE RULE** — surface shows nothing after 5 min? Switch surfaces.
- **1-HOUR RULE** — stuck with no progress? Switch context.
- **20-MINUTE ROTATION** — "Am I making progress?" If no, rotate.
- **45-MINUTE RULE** — stuck on one param? STOP. Rabbit hole. Move on.

Next: [[Methodology]] → [[Trust Map]]
