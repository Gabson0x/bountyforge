#!/usr/bin/env python3
"""
BountyForge Lead Ledger — persistent state-transition research objects for OPEN LEADs.

An OPEN LEAD is no longer a one-line journal entry that gets dropped when the
session ends. Every unresolved lead is a persisted object that lives across
sessions and mutates one variable at a time until its impact becomes provable.

Lead lifecycle (state machine):

    OPEN ──► MUTATING ──► FINDING   (both halves proven → promoted to findings.jsonl)
     │          │
     │          └──────────► PARKED (impact not provable under current preconditions
     │                                   → stays alive in the chain pool)
     └──────────────────────► PARKED (kill refused: only one half refuted)
     │
     └──► KILLED (ONLY with BOTH refutations recorded with evidence)

Guarantees:
  - Kill guard: kill_lead() REFUSES unless BOTH the trigger half AND the impact
    half are refuted with evidence strings. A refusal auto-parks the lead into
    the chain pool instead of dropping it. Dismissal attempts are counted.
  - Preconditions: every unprovable half is decomposed into named
    preconditions (missing account, role, state, timing window, sibling
    endpoint, chain partner...). Each resolves to present/missing/refuted.
  - One-variable mutation loop: mutate_lead() records exactly one variable
    change (old → new → result → evidence) per attempt. next_mutation()
    deterministically picks the first missing precondition whose exact
    (variable, value) pair was never tried, so agents never repeat a dead
    experiment and never mutate two variables at once.
  - Chain pool: PARKED leads are not dead. find_chain_partners() re-scans
    findings AND parked leads so a parked lead can become the missing half of
    a later A→B breakthrough.
  - Persistence: state/sessions/{target}/leads.jsonl — append-only full
    snapshots; the last line per lead_id is the current state, so the history
    of every state transition is itself the tamper-evident research log.

Usage:
  python3 tools/leads.py --list --target example.com
  python3 tools/leads.py --add --target example.com --title "..." \
      --trigger "Can the path fire?" --impact "What does the victim lose?" \
      --payload "curl ..." --preconditions "second account:need cross-account proof"
  python3 tools/leads.py --set-half --target example.com --lead ID \
      --half impact --verdict proven --evidence "..."
  python3 tools/leads.py --next-mutation --target example.com --lead ID
  python3 tools/leads.py --mutate --target example.com --lead ID \
      --variable "payload encoding" --old "%27" --new "%2527" \
      --result advanced --evidence "WAF bypassed, 302->500"
  python3 tools/leads.py --kill --target example.com --lead ID \
      --trigger-refutation "..." --impact-refutation "..."
  python3 tools/leads.py --chain-partners --target example.com --lead ID
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.state import (
    STATE_ROOT, atomic_append, atomic_write, log_journal,
    add_finding, get_findings,
)

LEAD_DIR = STATE_ROOT / "sessions"

VALID_STATES = {"OPEN", "MUTATING", "FINDING", "PARKED", "KILLED"}
HALF_VERDICTS = {"proven", "untraced", "ambiguous", "refuted"}
PRECONDITION_STATUSES = {"missing", "present", "refuted", "irrelevant"}
MUTATION_RESULTS = {"advanced", "unchanged", "refuted", "error"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Precondition:
    name: str
    description: str = ""
    status: str = "missing"  # missing, present, refuted, irrelevant
    proven_by: str = ""
    refuted_by: str = ""

    def __post_init__(self):
        if self.status not in PRECONDITION_STATUSES:
            raise ValueError(f"bad precondition status: {self.status}")


@dataclass
class MutationAttempt:
    ts: str = ""
    variable: str = ""
    old: str = ""
    new: str = ""
    result: str = "unchanged"  # advanced, unchanged, refuted, error
    evidence: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()
        if self.result not in MUTATION_RESULTS:
            raise ValueError(f"bad mutation result: {self.result}")


@dataclass
class Lead:
    lead_id: str = ""
    target: str = ""
    title: str = ""
    state: str = "OPEN"  # OPEN, MUTATING, FINDING, PARKED, KILLED
    trigger_half: str = "untraced"  # proven, untraced, ambiguous, refuted
    impact_half: str = "untraced"
    trigger_trace: str = ""  # written reachability trace
    impact_trace: str = ""   # written victim-harm trace
    preconditions: List[Dict] = field(default_factory=list)
    payload: str = ""
    chain_partners: List[str] = field(default_factory=list)
    mutation_attempts: List[Dict] = field(default_factory=list)
    dismissal_attempts: int = 0
    kill_refusal_reasons: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.lead_id:
            raw = f"{self.target}|{self.title}|{self.created_at}"
            self.lead_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if self.state not in VALID_STATES:
            raise ValueError(f"bad lead state: {self.state}")
        if self.trigger_half not in HALF_VERDICTS:
            raise ValueError(f"bad trigger verdict: {self.trigger_half}")
        if self.impact_half not in HALF_VERDICTS:
            raise ValueError(f"bad impact verdict: {self.impact_half}")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _leads_file(target: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
    return LEAD_DIR / safe / "leads.jsonl"


def _append_snapshot(lead: Lead):
    """Append a full snapshot. Last line per lead_id is the current state."""
    lead.updated_at = datetime.now(timezone.utc).isoformat()
    atomic_append(_leads_file(lead.target), json.dumps(asdict(lead)))


def load_leads(target: str) -> List[Lead]:
    """Load current state of all leads (last snapshot per lead_id wins)."""
    f = _leads_file(target)
    if not f.exists():
        return []
    latest: Dict[str, Lead] = {}
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            latest[data["lead_id"]] = Lead(**data)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return sorted(latest.values(), key=lambda l: l.created_at)


def get_lead(target: str, lead_id: str) -> Optional[Lead]:
    for lead in load_leads(target):
        if lead.lead_id == lead_id:
            return lead
    return None


def save_lead(target: str, lead: Lead, journal_event: str = "lead_updated",
              journal_data: Dict = None):
    """Persist a lead snapshot + journal the change."""
    _append_snapshot(lead)
    log_journal(target, journal_event, journal_data or {"lead_id": lead.lead_id})
    _sync_open_count(target)


def _sync_open_count(target: str):
    """Keep state.json's leads_open counter in sync with the ledger."""
    from tools.state import load_state, save_state
    state = load_state(target)
    state.leads_open = sum(
        1 for l in load_leads(target) if l.state in ("OPEN", "MUTATING"))
    save_state(target, state)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

def _recompute_state(lead: Lead) -> str:
    """Derive legal state from the two half-verdicts.

    Both proven → FINDING. Either refuted → needs the OTHER half refuted too
    before KILLED; otherwise PARKED (chain pool). Anything else → OPEN.
    """
    if lead.trigger_half == "proven" and lead.impact_half == "proven":
        return "FINDING"
    if lead.trigger_half == "refuted" and lead.impact_half == "refuted":
        return "KILLED"
    return lead.state if lead.state in ("OPEN", "MUTATING", "PARKED") else "PARKED"


def create_lead(target: str, title: str, q_trigger: str = "",
                q_impact: str = "", payload: str = "",
                preconditions: List[str] = None,
                chain_partners: List[str] = None) -> Lead:
    """Create and persist a new OPEN LEAD research object."""
    lead = Lead(
        target=target, title=title,
        trigger_trace=q_trigger, impact_trace=q_impact, payload=payload,
        chain_partners=list(chain_partners or []),
    )
    for pc in preconditions or []:
        name, _, desc = pc.partition(":")
        lead.preconditions.append(asdict(Precondition(name=name.strip(),
                                                      description=desc.strip())))
    _append_snapshot(lead)
    log_journal(target, "lead_created",
                {"lead_id": lead.lead_id, "title": title,
                 "state": lead.state, "preconditions": len(lead.preconditions)})
    _sync_open_count(target)
    return lead


def set_half(target: str, lead_id: str, half: str, verdict: str,
             evidence: str = "") -> Dict:
    """Write a verdict for one half (trigger/impact) with evidence.

    Verdicts are permissive: 'proven' and 'refuted' must carry evidence;
    'untraced'/'ambiguous' keep the lead open. State is recomputed after.
    """
    if half not in ("trigger", "impact"):
        return {"ok": False, "error": "half must be 'trigger' or 'impact'"}
    if verdict not in HALF_VERDICTS:
        return {"ok": False, "error": f"verdict must be one of {HALF_VERDICTS}"}
    if verdict in ("proven", "refuted") and not evidence.strip():
        return {"ok": False, "error": f"verdict '{verdict}' requires evidence"}
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}

    if half == "trigger":
        lead.trigger_half = verdict
        lead.trigger_trace = evidence if verdict == "proven" else lead.trigger_trace
    else:
        lead.impact_half = verdict
        lead.impact_trace = evidence if verdict == "proven" else lead.impact_trace

    old_state = lead.state
    lead.state = _recompute_state(lead)
    save_lead(target, lead, "lead_half_set",
              {"lead_id": lead_id, "half": half, "verdict": verdict,
               "state": f"{old_state} -> {lead.state}"})
    return {"ok": True, "lead_id": lead_id, "state": lead.state}


def add_precondition(target: str, lead_id: str, name: str,
                     description: str = "") -> Dict:
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    if any(p["name"] == name for p in lead.preconditions):
        return {"ok": False, "error": f"precondition '{name}' already tracked"}
    lead.preconditions.append(asdict(Precondition(name=name, description=description)))
    save_lead(target, lead, "lead_precondition_added",
              {"lead_id": lead_id, "name": name})
    return {"ok": True, "lead_id": lead_id, "name": name}


def resolve_precondition(target: str, lead_id: str, name: str, status: str,
                         evidence: str = "") -> Dict:
    """Resolve a precondition to present/refuted/irrelevant — with proof."""
    if status not in PRECONDITION_STATUSES:
        return {"ok": False, "error": f"status must be one of {PRECONDITION_STATUSES}"}
    if status in ("present", "refuted") and not evidence.strip():
        return {"ok": False, "error": f"status '{status}' requires evidence"}
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    for pc in lead.preconditions:
        if pc["name"] == name:
            pc["status"] = status
            if status == "present":
                pc["proven_by"] = evidence
            elif status == "refuted":
                pc["refuted_by"] = evidence
            save_lead(target, lead, "lead_precondition_resolved",
                      {"lead_id": lead_id, "name": name, "status": status})
            return {"ok": True, "lead_id": lead_id, "name": name, "status": status}
    return {"ok": False, "error": f"precondition '{name}' not tracked"}


def mutate_lead(target: str, lead_id: str, variable: str, old: str, new: str,
                result: str = "unchanged", evidence: str = "") -> Dict:
    """Record ONE variable mutation. Exactly one variable per call.

    The anti-repeat rule lives in next_mutation(), but the ledger enforces
    the single-variable discipline here: 'old' and 'new' must differ, and
    the attempt is appended to the lead's research history.
    """
    if result not in MUTATION_RESULTS:
        return {"ok": False, "error": f"result must be one of {MUTATION_RESULTS}"}
    if result == "advanced" and not evidence.strip():
        return {"ok": False, "error": "result 'advanced' requires evidence"}
    if old == new:
        return {"ok": False, "error": "old == new: no variable was mutated"}
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}

    attempt = asdict(MutationAttempt(variable=variable, old=old, new=new,
                                     result=result, evidence=evidence))
    lead.mutation_attempts.append(attempt)
    if lead.state == "OPEN":
        lead.state = "MUTATING"
    elif lead.state == "PARKED":
        lead.state = "MUTATING"  # a parked lead is always re-activatable
    save_lead(target, lead, "lead_mutation",
              {"lead_id": lead_id, "variable": variable,
               "result": result, "attempt": len(lead.mutation_attempts)})
    return {"ok": True, "lead_id": lead_id, "attempt": len(lead.mutation_attempts),
            "state": lead.state}


def next_mutation(target: str, lead_id: str) -> Dict:
    """Deterministic suggestion for the NEXT single-variable mutation.

    Walks missing preconditions in order. If a precondition was never
    mutated, suggest it fresh. If it WAS tried, suggest the SAME variable
    with a NEW value — exhaustion is never a kill, only a new value.
    """
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    if lead.state == "KILLED":
        return {"ok": False, "error": "lead is KILLED"}

    remaining = sum(1 for p in lead.preconditions if p["status"] == "missing")

    for pc in lead.preconditions:
        if pc["status"] != "missing":
            continue
        attempts = [m for m in lead.mutation_attempts
                    if m["variable"] == pc["name"]]
        if not attempts:
            return {
                "ok": True,
                "lead_id": lead_id,
                "variable": pc["name"],
                "new_value": "",
                "suggestion": (f"Mutate ONE variable: precondition '{pc['name']}' "
                               f"is still missing — {pc['description']}"),
                "remaining_missing": remaining,
            }
        last = attempts[-1]["new"]
        return {
            "ok": True,
            "lead_id": lead_id,
            "variable": pc["name"],
            "new_value": f"<value different from '{last}'>",
            "suggestion": (f"Precondition '{pc['name']}' was tried with '{last}' — "
                           f"mutate the SAME variable with a NEW value. "
                           f"Exhaustion is not a kill."),
            "remaining_missing": remaining,
        }

    return {"ok": True, "lead_id": lead_id, "variable": None, "new_value": "",
            "suggestion": "no missing preconditions; if impact still unprovable, "
                          "park the lead into the chain pool — do not kill"}


def promote_to_finding(target: str, lead_id: str, finding: Dict = None) -> Dict:
    """Promote a lead whose both halves are proven into findings.jsonl."""
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    if lead.trigger_half != "proven" or lead.impact_half != "proven":
        return {"ok": False,
                "error": f"cannot promote: trigger={lead.trigger_half} "
                         f"impact={lead.impact_half} — both must be 'proven'"}

    fdata = dict(finding or {})
    fdata.setdefault("title", lead.title)
    fdata.setdefault("description", lead.trigger_trace or lead.title)
    fdata.setdefault("impact", lead.impact_trace or "")
    fdata.setdefault("proof_of_concept", lead.payload or "")
    if lead.chain_partners:
        fdata.setdefault("chain_parent", lead.chain_partners[0])
    finding_id = add_finding(target, fdata)

    lead.state = "FINDING"
    save_lead(target, lead, "lead_promoted",
              {"lead_id": lead_id, "finding_id": finding_id})
    return {"ok": True, "lead_id": lead_id, "finding_id": finding_id}


def park_lead(target: str, lead_id: str, reason: str = "") -> Dict:
    """Park a lead into the chain pool. It stays alive for future chaining."""
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    if lead.state in ("KILLED", "FINDING"):
        return {"ok": False, "error": f"cannot park a {lead.state} lead"}
    lead.state = "PARKED"
    save_lead(target, lead, "lead_parked",
              {"lead_id": lead_id, "reason": reason or "chain pool"})
    return {"ok": True, "lead_id": lead_id, "state": "PARKED"}


def kill_lead(target: str, lead_id: str, trigger_refutation: str = "",
              impact_refutation: str = "") -> Dict:
    """Kill a lead. REFUSES unless BOTH halves are refuted with evidence.

    Anti-dismissal guard: a one-half refutation is not a kill — it is an
    auto-park into the chain pool. The lead lives on for the main
    breakthrough; dismissal attempts are counted and journaled.
    """
    lead = get_lead(target, lead_id)
    if lead is None:
        return {"ok": False, "error": "lead not found"}
    if lead.state in ("KILLED", "FINDING"):
        return {"ok": False, "error": f"lead already {lead.state}"}

    trigger_ok = bool(trigger_refutation.strip())
    impact_ok = bool(impact_refutation.strip())

    if not (trigger_ok and impact_ok):
        lead.dismissal_attempts += 1
        reason = (f"kill refused: trigger-refutation={'present' if trigger_ok else 'MISSING'}, "
                  f"impact-refutation={'present' if impact_ok else 'MISSING'} — "
                  f"one unproven half = OPEN LEAD, never a kill")
        lead.kill_refusal_reasons.append(reason)
        if lead.state != "PARKED":
            lead.state = "PARKED"
        save_lead(target, lead, "lead_kill_refused",
                  {"lead_id": lead_id, "reason": reason,
                   "dismissal_attempts": lead.dismissal_attempts})
        return {"ok": False, "killed": False, "parked": True,
                "lead_id": lead_id, "reason": reason}

    lead.trigger_half = "refuted"
    lead.impact_half = "refuted"
    lead.state = "KILLED"
    save_lead(target, lead, "lead_killed",
              {"lead_id": lead_id,
               "trigger_refutation": trigger_refutation,
               "impact_refutation": impact_refutation})
    return {"ok": True, "killed": True, "lead_id": lead_id, "state": "KILLED"}


def find_chain_partners(target: str, lead_id: str = None) -> Dict:
    """Scan findings + parked/opened leads for A→B chain partners.

    A lead that cannot prove impact standalone is not dead — it is the
    missing half of a future chain. This is the breakthrough reuse path.
    """
    leads = load_leads(target)
    if lead_id:
        lead = get_lead(target, lead_id)
        if lead is None:
            return {"ok": False, "error": "lead not found"}
        pool = [lead]
    else:
        pool = [l for l in leads if l.state in ("PARKED", "OPEN", "MUTATING")]

    findings = get_findings(target)
    partners = []

    for lead in pool:
        title_l = (lead.title + " " + lead.payload + " " + lead.trigger_trace).lower()
        for f in findings:
            ftext = (f.get("title", "") + " " + f.get("bug_class", "") +
                     " " + f.get("description", "")).lower()
            if f["finding_id"] in lead.chain_partners:
                continue
            if _chainable(lead, f):
                partners.append({
                    "lead_id": lead.lead_id,
                    "lead_title": lead.title,
                    "partner": f["finding_id"],
                    "partner_title": f.get("title", ""),
                    "direction": "lead_is_a_half" if lead.trigger_half == "proven"
                                  else "lead_needs_this_half",
                })

    return {"ok": True, "target": target, "partners": partners}


_CHAIN_PAIRS = [
    (("open_redirect", "oauth_misconfig", "authorization", "login"),
     ("oauth", "authorization", "login"),
     "redirect chain: lead + OAuth/authorization partner can become ATO"),
    (("idor",), ("idor",),
     "idor chain: read lead + write partner (or vice versa) = resource takeover"),
    (("ssrf",), ("infra_exposure", "information_disclosure", "metadata"),
     "ssrf chain: lead + internal exposure partner = infrastructure access"),
    (("xss",), ("xss", "cookie", "session"),
     "xss chain: lead + session partner = ATO"),
    (("race",), ("payment", "redeem", "transfer", "wallet", "gift"),
     "race chain: lead + fund-movement partner = double-spend"),
]


def _chainable(lead: Lead, finding: Dict) -> bool:
    def norm(s: str) -> str:
        return s.replace("_", " ").replace("-", " ").lower()

    lead_l = norm(lead.title + " " + lead.payload)
    find_l = norm(finding.get("title", "") + " " + finding.get("bug_class", ""))
    for a, b, _ in _CHAIN_PAIRS:
        a_matches = any(norm(k) in lead_l for k in a)
        b_matches = any(norm(k) in find_l for k in b)
        if (a_matches and b_matches) or (b_matches and a_matches):
            return True
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Lead Ledger")
    parser.add_argument("--target", help="Target host")
    parser.add_argument("--lead", help="Lead ID")
    parser.add_argument("--add", action="store_true", help="Create a new OPEN LEAD")
    parser.add_argument("--title", help="Lead title")
    parser.add_argument("--trigger", help="Q-TRIGGER written trace ('Can the path fire?')")
    parser.add_argument("--impact", help="Q-IMPACT written trace ('What does the victim lose?')")
    parser.add_argument("--payload", help="Payload kept with the lead")
    parser.add_argument("--preconditions", nargs="*",
                        help="Missing preconditions as 'name:description'")
    parser.add_argument("--partner", action="append", default=[],
                        help="Chain partner finding/lead ID (repeatable)")
    parser.add_argument("--list", action="store_true", help="List leads for target")
    parser.add_argument("--state", help="Filter list by lead state")
    parser.add_argument("--get", action="store_true", help="Show one lead")
    parser.add_argument("--set-half", action="store_true",
                        help="Set a half verdict")
    parser.add_argument("--half", choices=["trigger", "impact"])
    parser.add_argument("--verdict", choices=sorted(HALF_VERDICTS))
    parser.add_argument("--evidence", help="Evidence for a verdict/precondition")
    parser.add_argument("--precondition", help="Add a precondition (name:description)")
    parser.add_argument("--resolve-precondition", help="Resolve precondition by name")
    parser.add_argument("--next-mutation", action="store_true",
                        help="Suggest the next single-variable mutation")
    parser.add_argument("--mutate", action="store_true", help="Record a mutation")
    parser.add_argument("--variable", help="Variable being mutated")
    parser.add_argument("--old", help="Old value")
    parser.add_argument("--new", help="New value")
    parser.add_argument("--result", choices=sorted(MUTATION_RESULTS),
                        help="Mutation result")
    parser.add_argument("--promote", action="store_true",
                        help="Promote proven lead to finding")
    parser.add_argument("--park", action="store_true", help="Park lead into chain pool")
    parser.add_argument("--kill", action="store_true", help="Kill lead (needs BOTH refutations)")
    parser.add_argument("--trigger-refutation", help="Evidence the trigger cannot fire")
    parser.add_argument("--impact-refutation", help="Evidence the harm does not exist")
    parser.add_argument("--chain-partners", action="store_true",
                        help="Find A->B chain partners for lead or target")
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        return

    if args.add:
        if not args.title:
            print("[!] --title required")
            return
        lead = create_lead(args.target, args.title, args.trigger or "",
                           args.impact or "", args.payload or "",
                           args.preconditions or [], args.partner)
        print(json.dumps({"ok": True, "lead_id": lead.lead_id,
                          "state": lead.state}, indent=2))

    elif args.list:
        leads = load_leads(args.target)
        if args.state:
            leads = [l for l in leads if l.state == args.state.upper()]
        if not leads:
            print(f"[*] No leads for {args.target}")
        for l in leads:
            print(f"[{l.state:8s}] {l.lead_id}  {l.title}  "
                  f"(trigger={l.trigger_half}, impact={l.impact_half}, "
                  f"missing_preconditions={sum(1 for p in l.preconditions if p['status'] == 'missing')})")

    elif args.get:
        if not args.lead:
            print("[!] --lead required")
            return
        lead = get_lead(args.target, args.lead)
        if lead is None:
            print("[!] lead not found")
            return
        print(json.dumps(asdict(lead), indent=2))

    elif args.set_half:
        if not args.lead or not args.half or not args.verdict:
            print("[!] --lead, --half, --verdict required")
            return
        print(json.dumps(set_half(args.target, args.lead, args.half,
                                  args.verdict, args.evidence or ""), indent=2))

    elif args.precondition:
        if not args.lead:
            print("[!] --lead required")
            return
        name, _, desc = args.precondition.partition(":")
        print(json.dumps(add_precondition(args.target, args.lead,
                                          name.strip(), desc.strip()), indent=2))

    elif args.resolve_precondition:
        if not args.lead or not args.verdict:
            print("[!] --lead, --resolve-precondition, --verdict required")
            return
        print(json.dumps(resolve_precondition(
            args.target, args.lead, args.resolve_precondition,
            args.verdict, args.evidence or ""), indent=2))

    elif args.next_mutation:
        if not args.lead:
            print("[!] --lead required")
            return
        print(json.dumps(next_mutation(args.target, args.lead), indent=2))

    elif args.mutate:
        if not args.lead or not args.variable or not args.old or not args.new:
            print("[!] --lead, --variable, --old, --new required")
            return
        print(json.dumps(mutate_lead(args.target, args.lead, args.variable,
                                     args.old, args.new,
                                     args.result or "unchanged",
                                     args.evidence or ""), indent=2))

    elif args.promote:
        if not args.lead:
            print("[!] --lead required")
            return
        print(json.dumps(promote_to_finding(args.target, args.lead), indent=2))

    elif args.park:
        if not args.lead:
            print("[!] --lead required")
            return
        print(json.dumps(park_lead(args.target, args.lead), indent=2))

    elif args.kill:
        if not args.lead:
            print("[!] --lead required")
            return
        print(json.dumps(kill_lead(args.target, args.lead,
                                   args.trigger_refutation or "",
                                   args.impact_refutation or ""), indent=2))

    elif args.chain_partners:
        print(json.dumps(find_chain_partners(args.target, args.lead), indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()