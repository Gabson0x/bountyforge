# Severity Mapping

Use this baseline when program-specific rules do not override it.

- `Critical`: Direct, realistic loss of funds or full protocol compromise with clear attacker path.
- `High`: Major security impact (privilege escalation, substantial theft, permanent denial of service) with practical exploitability.
- `Medium`: Meaningful security weakness with constrained impact or stronger preconditions.
- `Low`: Limited impact, narrow edge case, or low-likelihood abuse.
- `None`: Best-practice issue without material security impact.

## Adjustments

- Raise severity when exploit path is simple, repeatable, and low-cost.
- Lower severity when exploit needs privileged access, unrealistic assumptions, or excessive coordination.
- Anchor final severity to demonstrated impact, not hypothetical worst case.
