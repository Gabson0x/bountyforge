# Triage Comment Templates

Use short markdown comments and keep them evidence-based.

## Valid and Triaged

```md
Thanks for the report.

We validated the issue and confirmed the following:
- **Impact**: <clear impact>
- **Reproducibility**: <reproduced/noted from PoC>
- **Scope**: In scope

We are marking this report as **Triaged** with severity **<severity>**.
```

## Need More Info

```md
Thanks for the submission.

We could not fully validate the issue yet. Please provide:
- <missing step or environment details>
- <expected vs actual behavior evidence>
- <PoC artifact, logs, or transaction links>

We are setting this to **Need more info** until the additional details are shared.
```

## Out of Scope

```md
Thanks for your report.

After review, this issue is currently **Out of scope** for this program because:
- <specific scope/rule reference>

If you believe this maps to a different in-scope target, share that target and evidence and we will re-check.
```

## Duplicate

```md
Thanks for the submission.

This issue matches an existing report with the same root cause and impact: **<report-id>**.

We are marking this report as **Duplicate**.
```
