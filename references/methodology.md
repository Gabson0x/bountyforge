# Methodology — 5 Pillars, 6 Rules, 5 Questions

**The architecture-first spine of every hunt.** Always loaded. This is the structure that
keeps the AI from "going off in all directions" — it forces the hunt to run *through* the
engine (the `tools/` and the maps in `state/`), not on instinct alone.

> Wild-mode (`references/wild-mode.md`) is the *mindset* applied **within** this structure:
> no ceilings, payload-first, chain-or-die. This document is the *skeleton*: five maps and
> six rules that tell you **where** to point that mindset.

---

## The Core Shift: Architecture, Not Endpoints

Don't start with individual endpoints. Start by mapping the whole system, then hunt the
**gaps and intersections**. The gold is almost never a single endpoint — it's the boundary
between two things, the state transition the developer forgot to validate, or the interface
that wasn't updated when its sibling was.

> **No map → no hunt.** An endpoint that isn't located in one of the 5 maps is not yet a
> target. Map it first, then probe. This single constraint is what stops the AI from going
> off in all directions.

---

## The Hunt Loop (10 steps)

Every hunt runs this loop, in order:

1. **BUILD MAPS** — all 5 pillars (P1→P5).
2. **IDENTIFY GAPS** — where assets differ (P1), where trust crosses a boundary (P2), where
   an authz cell is `untested` (P3), where an illegal state transition exists (P4), where a
   capability has authority/economic reach (P5).
3. **SELECT AN INTERSECTION** — `identity × object × state × boundary × interface`.
4. **FORM HYPOTHESIS** — a specific "attacker can X → causing Y" claim, expressible as a map
   mutation (Rule 2).
5. **MUTATE ONE VARIABLE** — change exactly one thing (`user_id`, `role`, version, state,
   amount, recipient, method, content-type, token…).
6. **OBSERVE DELTA** — what changed in the response/behavior? Log the "no"s too (Rule 7 in
   wild-mode).
7. **REFUTE OR ESCALATE** — try to kill your own finding (`tools/refutation.py`); if it
   survives, escalate.
8. **CHAIN CAPABILITIES** — what does this lead combine with? (`tools/kill_chain.py`)
9. **VALIDATE IMPACT** — real harm to a real victim? (supervisor gates)
10. **REPORT** — only findings that survive the gates.

---

## The 5 Pillars (maps)

Every hunt maintains all five. These are **mandatory state** — not notes, not optional
summaries. The canonical map directory is:

```
state/sessions/{target}/maps/
├── asset.md        # P1 — what exists + gaps
├── trust.md        # P2 — who trusts whom
├── authz.md        # P3 — action × actor matrix
├── state.md        # P4 — object → states → transitions
├── capability.md   # P5 — capability + impact verb + boundary
└── invariants.md   # (contract hunts) protocol invariants + value at risk — fed by P1–P5
```

If a map file doesn't exist yet, create it before hunting that dimension. Every agent must
reference these files; every finding must trace back to a location in one of them (Rule 6).

### P1 — Asset Map (Surface)

**Question:** "What exists, and what's different between assets?"

Inventory every asset, then find what is *different* between assets. The gaps are the gold.

Build an inventory of:
- Domains / subdomains
- APIs and API versions
- Mobile apps
- Web apps
- GraphQL
- WebSockets
- Cloud assets
- GitHub / source leaks
- Third-party integrations
- Authentication / SSO
- Admin / internal panels
- Smart contracts and bridges (Web3)

**Schema** — write to `state/sessions/{target}/maps/asset.md`:

```markdown
| asset_id | type | technology | functionality | auth | versions | gaps[] |
|---|---|---|---|---|---|---|
| api-v2.example.com | api_version | Go/gRPC | withdraw, transfer | bearer | v2 | withdraw missing amount cap (v1 has it) |
```

Types: `domain, subdomain, api, api_version, mobile, web, graphql, websocket, cloud,
github, integration, sso, admin, smart_contract, bridge`.

`gaps[]` is the money column: every time two assets expose the same functionality with
different auth/validation/versions, that row is a lead.

### P2 — Trust Map (Boundaries)

**Question:** "Where does the system trust something it shouldn't?"

A directed graph of who trusts whom, for what, how strongly. Boundaries to enumerate:
client→API, user→organization, org A→org B, regular user→admin, API v1→API v2,
backend→third-party, L1→L2, contract A→contract B.

**Schema** — write to `state/sessions/{target}/maps/trust.md`:

```markdown
| trustor | trustee | trust_type | strength | boundary_crossed |
|---|---|---|---|---|
| client | api | token_based | 0.7 | public→private |
| user | admin | header_based (X-Forwarded-For) | 0.9 | user→admin |
```

**Engine:** `tools/trust_map.py` (exists — full graph + boundary-crossing detection). Backs
the markdown with a queryable graph:

```bash
python3 tools/trust_map.py --target {target} --init
python3 tools/trust_map.py --target {target} --add-edge '{...}'      # as recon reveals trust
python3 tools/trust_map.py --target {target} --find-crossings        # ⚡ the payoff
python3 tools/trust_map.py --target {target} --find-chains
```

High-impact bugs live at trust-boundary crossings. A crossing from an outside node to an
inside node, over a `no_auth`/`header_based`/`ip_based`/`internal_skip` edge, is a critical
signal.

### P3 — Identity Map (Authorization Matrix)

**Question:** "Who is allowed to do this — and to whose data?"

Actors form a ladder: `anonymous → user → verified user → organization member → admin →
service`. For every important function, fill the matrix:

| Action | anonymous | user_a | user_b | org_member_a | org_admin_b | admin | service |
|---|---|---|---|---|---|---|---|
| Read own data | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Read A's data | ? | ✓ | ? | ? | ? | ✓ | ✓ |
| Modify A's data | ? | ✓ | ? | ? | ? | ✓ | ✓ |
| Delete A's data | ? | ✓ | ? | ? | ? | ✓ | ✓ |
| Admin action | ? | ? | ? | ? | ? | ✓ | ✓ |

Don't just test `GET /api/user/123`. Test the **relationship**: user A → user B's resource,
then user A → organization B, then user A → admin functionality. The `?` cells are where
IDOR/BOLA, privilege escalation, and tenant-isolation bugs emerge.

**Schema** — write to `state/sessions/{target}/maps/authz.md` (same table, with
`allowed`/`denied`/`untested` per cell).

**Engine:** `tools/hunt.py` dual-session diff (exists) — every `untested` cell becomes a
probe:

```bash
python3 tools/hunt.py --target {target} --auth-file .private/{target}-user-a.json
python3 tools/hunt.py --target {target} --auth-file .private/{target}-user-b.json
```

### P4 — State Map (State Machine)

**Question:** "Can I force a state the developers didn't anticipate?"

For every stateful object, map states + allowed transitions, then attack the *illegal*
ones.

```
Created → Pending → Approved → Completed
```

Attack: `Created→Completed` (skip), `Approved→Pending` (reverse), `Completed→Approved`
(reverse), `Pending→Completed→Completed` (double). Look for missing state validation, race
conditions, replay, double-spend, duplicate transactions, cancel-after-completion,
refund-after-withdrawal, approval bypass, TOCTOU.

**Schema** — write to `state/sessions/{target}/maps/state.md`:

```markdown
| object | states[] | allowed_transitions[] | illegal_transitions[] | race_points[] |
|---|---|---|---|---|
| withdrawal | created,pending,approved,completed,cancelled | created→pending→approved→completed | pending→completed (skip), completed→approved (reverse), completed→completed (double) | approve vs cancel |
```

**Engine:** `tools/kill_chain.py` (exists) — state transitions become chain nodes; a
state-machine bug that chains into a money/authority primitive scores high.

### P5 — Capability & Authority Map

**Question:** "What can this capability **create, approve, modify, transfer, withdraw,
impersonate, or authorize**?"

P5 owns **capability + economic/authority impact**. It's not just "weird functionality" —
it's the answer to "does this capability cross a meaningful security boundary, and what
does it let me *do* if it does?" Every capability gets an impact verb; a capability with no
impact verb is not yet understood.

Prioritize capabilities that map to these verbs (enormous bug density vs ordinary CRUD):

- **Money** — deposits, withdrawals, refunds, transfers, rewards, coupons (create/withdraw/transfer)
- **Identity** — password reset, email change, MFA, SSO, account linking (impersonate/authorize)
- **Permissions** — invitations, org roles, API keys, OAuth scopes, service accounts (approve/authorize/impersonate)
- **State** — cancellation, approval, verification, deletion, recovery (approve/modify)

**Schema** — write to `state/sessions/{target}/maps/capability.md`:

```markdown
| feature | capability | impact_verb | boundary_crossed | create | approve | modify | transfer | withdraw | impersonate | authorize |
|---|---|---|---|---|---|---|---|---|---|---|
| gift-card redeem | redeem(code) | withdraw | user→payment | user | — | support | user | user | — | — |
| org invite | invite(email, role) | authorize | user→admin | org_admin | — | org_admin | — | — | — | org_admin |
```

**Engine:** `tools/capability_registry.py` (register every capability), `tools/program_fit.py`
(does the program accept this bug class / does it cross a boundary the program cares about),
and `tools/kill_chain.py` (chain the capability into a bigger impact). Query cross-boundary
chains — a capability is only interesting when it crosses a meaningful boundary.

---

## The 6 Rules (non-negotiable)

1. **No map → no hunt.** Build all 5 maps before probing any endpoint. An endpoint that isn't
   located in a map is not yet huntable — map it first, then probe. The maps ARE the hunt;
   there is no endpoint-first mode.
2. **Every hypothesis is a map mutation.** A lead must be expressible as a node/edge/state/
   capability in one of the 5 maps. If you can't express it, you don't understand it yet.
   The engine is the source of truth, not instinct.
3. **Hunt intersections, not endpoints.** The unit of hunting is
   `identity × object × state × boundary × interface` — not `GET /api/user/123`.
4. **Differential over absolute.** Change exactly one variable and observe the delta:
   `user_id, organization_id, role, API version, HTTP method, content type, token, state,
   amount, recipient`. Same functionality on two interfaces (web / mobile / REST / GraphQL /
   admin API / old version) must be compared — developers fix one and forget the other.
5. **Automate discovery, manually reason impact.** Tools find mutations; the AI finds the
   assumption. Report gates apply at report time only (see wild-mode).
6. **Every finding has a map path.** A finding must trace back to a specific location in one
   of the 5 maps: `Finding → P3 → authz.md → user_a × withdrawal_b`, or
   `Finding → P4 → state.md → approved → cancelled`, or `Finding → P2 → trust.md → client →
   backend`, or `Finding → P5 → capability.md → transfer → authority boundary`. If an agent
   cannot name the map, node, edge, state transition, or capability involved, the finding is
   not mature enough to report.

---

## The 5 Questions (run on every feature)

1. **Who is allowed to do this?** (P3)
2. **What exactly does the server trust from the client?** (P2)
3. **What happens if I change the identity / object / state?** (P3 / P4)
4. **What happens if I perform the operation twice or concurrently?** (P4)
5. **Can I chain this behavior into money, data, or privilege?** (P5 + kill_chain)

---

## The Intersection Formula

A good hunting hypothesis is an **intersection**, not a scan:

```
identity × object × state × boundary × interface
```

**Every finding must be written as an intersection**, not as "an interesting endpoint":

```
Intersection:
Identity: user_a
Object: withdrawal_123
State: approved
Boundary: user → financial capability
Interface: API v2

Hypothesis: user_a can modify an approved withdrawal belonging to user_b.
```

This is what "think in the architecture" means — the model is forced to name each dimension
before it is allowed to call something a finding. The intersection plus its map path
(Rule 6) is the minimum bar for a mature finding.

---

## Tool → Pillar Mapping

| Pillar | Mandatory state | Engine |
|---|---|---|
| P1 Asset Map | `maps/asset.md` | — |
| P2 Trust Map | `maps/trust.md` | `tools/trust_map.py` |
| P3 Identity Map | `maps/authz.md` | `tools/hunt.py` (dual-session diff) |
| P4 State Map | `maps/state.md` | `tools/kill_chain.py` |
| P5 Capability & Authority Map | `maps/capability.md` | `tools/capability_registry.py` + `tools/program_fit.py` + `tools/kill_chain.py` |
| Cross-cutting: primitives | — | `tools/capability_registry.py` |
| Cross-cutting: chains | — | `tools/kill_chain.py` |
| Cross-cutting: validation | — | `tools/refutation.py`, `tools/program_fit.py`, `tools/adversary_emulation.py` |

The six `.md` map files under `state/sessions/{target}/maps/` are **mandatory state** —
every hunt creates them, every agent references them, every finding traces back to one. The
engine tools back them with queryable graphs where available. The sixth, `invariants.md`, is
a cross-cutting map for contract hunts — fed by P1–P5, and the entry point for every
smart-contract finding (see the Smart-Contract Track below).

---

## Smart-Contract Track — Protocol & Economic-State Aware

For `--solidity` / `--move` / `--solana` targets the spine is the same, but the **unit of
analysis changes from "endpoint" to "economic invariant."** A contract's correctness is a
property of its solvency, supply, permission, and price relationships — not of any single
function. The maps describe the *protocol* (contracts **and** their external dependencies),
not a file list. Map the protocol first, hunt the invariant break second; implementation
bugs (reentrancy, overflow) are what's left after the accounting is proven sound.

### The cross-cutting map: `invariants.md` (mandatory for contract hunts)

An invariant is a relationship that must hold across **every** transition. The bug is a
controlled variable that breaks one. `invariants.md` is the entry point for every contract
hunt — P1–P5 feed it, and every contract finding traces back to a row in it.

Schema — one row per invariant:

| invariant_id | description | affected_contracts | variables | preconditions | expected_relationship | mutation | observed_result | violated? | economic_consequence |
|---|---|---|---|---|---|---|---|---|---|

The four canonical invariant families:

- **Accounting / solvency** — `totalAssets() == Σ(getRate()·balance)`, `Σ userShares == totalSupply`. Break → mint/drain.
- **Supply** — mint == burn; no silent inflation (donation / first-depositor attack).
- **Permission** — only listed actors can call withdraw / transfer / authorize paths.
- **Price** — the oracle / rate feed is not manipulable within one block (flash-loan resistance).

### The economic hunt loop (contract edition)

The 10-step loop becomes, for contracts:

```
MAP → INVARIANT → IDENTIFY ASSUMPTION → FIND CONTROLLED VARIABLE → MUTATE
    → OBSERVE → CHECK INVARIANT → CHAIN → CALCULATE VALUE AT RISK
```

The delta only matters insofar as it breaks a stated invariant. The report is the
**value at risk** — the TVL the broken invariant unlocks — not "dangerous code." A finding
that can't name the invariant it breaks (and the value it puts at risk) is not mature enough
to report.

### The Web3 intersection formula

Contract findings are written as an 8-dimensional intersection, replacing the 5-dimensional
web formula:

```
IDENTITY × ASSET × STATE × PRICE × AUTHORITY × TRUST BOUNDARY × CALL GRAPH × TIME
```

- **IDENTITY** — the caller (EOA, contract, keeper, relayer, proxy admin, `msg.sender` vs stored owner).
- **ASSET** — what moves (shares, collateral, LP tokens, wrapped/rebasing assets).
- **STATE** — balances, ratios, `totalSupply`, `totalAssets` (economic, not status flags).
- **PRICE** — the external oracle / rate feed the protocol believes.
- **AUTHORITY** — the role / ownership path gating the transition.
- **TRUST BOUNDARY** — the external contract / feed the protocol delegates truth to.
- **CALL GRAPH** — the path from entry to the external call that carries the lie.
- **TIME** — block ordering / the single-block window (flash loans, front-running).

### The 12 points, folded into the pillars

| Point | Pillar | How it changes the map |
|---|---|---|
| Protocol mapping (contracts + deps, not files) | P1 | asset.md lists contracts **and** their external deps (oracles, rate providers, LPs, bridges, shared accountants) |
| External contracts as trust boundaries | P2 | trust.md edges to oracles/rate-providers/bridges are the critical crossings |
| Privilege graphs | P3 | authz.md actors become roles: owner, proxy-admin, keeper, multi-sig, `onlyRole` |
| Economic state machines + value-flow maps | P4 | state.md states are `totalSupply`/`totalAssets`/collateral ratio; transitions are mint/redeem/donate/vest/postLoss |
| Flash-loan-as-capability | P5 | capability.md registers "borrow unlimited liquidity for one block" as the highest-value primitive |
| Accounting before implementation | — | rank solvency/supply/price invariants before code-level bugs; reentrancy is what's left after accounting is sound |
| Economic differential testing | Rule 4 | the variable is an economic one (amount, rate, decimals, donation timing); the delta is denominated in value |
| Auto first-depositor hypothesis | default | every vault/share system is probed for donation inflation before anything else |
| Cross-contract invariant divergence | invariants.md | an invariant holding in A but broken when B is upgraded ("shared accountant") is a first-class row |
| Web3 intersection | Rule 3/6 | the 8-dimension formula replaces the 5-dimension one for contract findings |

The uncomfortable truth still holds: on sound audited code the critical lives at the
deploy-config / oracle-target layer and the fork-fuzz layer — both need live chain access,
not more file reads. The invariants tell you *what* to fuzz; fork + fuzz is *how* you prove
it.

---

## Summary

```
Map the surface (P1) → find trust boundaries (P2) → build the authz matrix (P3)
    → attack the state machine (P4) → map capability & authority (P5)
    → hunt the intersections → automate variation → reason about impact → chain → report

For contracts: map the protocol → list the invariants (`invariants.md`) → attack each
invariant with the economic loop → report value at risk.
```

Automation finds mutations. Humans find assumptions. The maps tell you where to look;
wild-mode tells you to never stop looking.
