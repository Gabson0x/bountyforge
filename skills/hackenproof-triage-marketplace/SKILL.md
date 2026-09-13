---
name: hackenproof-triage-marketplace
description: HackenProof bug bounty triage workflow for Claude Code plugin marketplace operations. Use when analyzing security reports, validating scope and exploitability, assigning severity, detecting duplicates, setting report state, adding labels/comments, and preparing consistent triage decisions for HackenProof programs.
---

# HackenProof Triage Marketplace

Execute consistent, evidence-based triage for HackenProof bug bounty reports.

## Workflow

1. Apply global HackenProof classification baseline from `references/hackenproof-global-policy.md`.
2. Run pre-validation gates in strict order:
   a. Verify the reported commit/version is the intended in-scope commit.
   b. Verify the submission target and impact are in scope.
   c. Verify PoC evidence is provided and readable.
   d. Verify whether an equivalent duplicate already exists.
3. Start technical validation only after all pre-validation gates pass.
4. Classify severity, choose state transition, and apply labels.
5. Post a concise decision comment with explicit rationale and next action.

## Mandatory Tool Sequence

1. Run `get_program_info` for scope and reward context.
2. Detect program type from `get_program_info` (for example: `web`, `mobile`, `smart-contract`, `blockchain`).
3. Map detected type to the equivalent vulnerability classification section in `references/hackenproof-global-policy.md`.
4. Run `get_report_details` to extract target, asset, and reported commit/version.
5. Run `get_attachments`; if no PoC evidence exists, set `Need more info` immediately.
6. Run `fetch_attachment` to confirm commit/version evidence in PoC files.
7. Compare commit/version against in-scope assets and versions from program rules.
8. Verify in-scope status for both target and claimed impact using program scope/rules, then global baseline if no override exists.
9. Run `list_reports`/`search_comments` to check duplicate candidates before validation.
10. Start validation: confirm reproducibility, impact, exploit preconditions, and proof quality.
11. Run `get_comments` before posting to avoid contradictory messaging.
12. Only then change `severity`, `state`, `labels`, and add comments.

## Pre-Validation Gates

### Gate 1: Commit or Version Match

- Confirm the submission references a concrete commit hash, tag, or release version.
- Confirm that commit/version maps to an in-scope repository, branch, deployment, or audit target.
- If commit/version is missing or mismatched, set `Need more info` and request exact commit evidence.

### Gate 2: Scope Match

- Confirm target asset is in scope.
- Confirm reported impact category is in scope for bounty eligibility.
- Confirm the finding matches the equivalent classification track for the detected program type.
- If either target or impact is excluded, mark `Out of scope` with explicit rule reference.

### Gate 3: Duplicate Check

- Search for same root cause and same impacted component before deep validation.
- Treat as duplicate only when both root cause and impact match an existing report.
- Add `dup-{report_id}` label when marking `Duplicate`.

### Gate 4: PoC Presence Check

- Confirm at least one usable PoC artifact exists (steps, payload, tx hash, video, logs, or attachment).
- If no PoC is provided, set `Need more info` and request concrete PoC evidence.

## Decision Rules

- Reject or mark `Need more info` when PoC is missing, commit/version evidence is missing, or reproduction steps are incomplete with no verifiable PoC.
- Mark `Out of scope` when target or impact is excluded by program scope/rules.
- Mark `Duplicate` only when matching root cause and impact are confirmed; add `dup-{report_id}` label.
- Use `Informative`/`Not applicable` for weak-impact findings that do not meet bounty criteria.
- Move valid reports to `Triaged` with severity aligned to program policy and demonstrated impact.

Use `references/severity-mapping.md` for impact-to-severity normalization.
Use `references/hackenproof-global-policy.md` for HackenProof-wide scope and severity baseline.
Use `references/triage-comment-templates.md` for consistent responder tone and structure.

## Quality Bar

- Ground every decision in concrete evidence from report fields, attachments, or program rules.
- Keep comments short, specific, and actionable; state exactly what is missing when requesting more info.
- Never guess exploitability when evidence is weak; request clarification instead.
- Prefer reversible actions (`Need more info`) over premature invalidation when uncertainty is material.
