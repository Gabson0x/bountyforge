#!/usr/bin/env python3
"""
BountyForge Adversarial Refutation Engine v3.0.0

Core rule: never trust a finding on its own word.

Spawns an adversarial model (different from the discovering agent) with one
objective: "You win if you kill this finding." Runs the 4-gate evaluation
(Refutation → Reachability → Trigger → Impact) from references/judging.md.
Only what survives all four gates is confirmed.

Usage:
  python3 tools/refutation.py --target example.com --finding-id abc123
  python3 tools/refutation.py --target example.com --all
  python3 tools/refutation.py --finding-file findings.jsonl --passes 3
  python3 tools/refutation.py --target example.com --finding-id abc123 --model haiku
"""

import json
import sys
import hashlib
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REFUTATION_DIR = ROOT / "state" / "refutations"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class GateResult(str, Enum):
    CLEARED = "cleared"
    REJECTED = "rejected"
    DEMOTED = "demoted"
    UNCERTAIN = "uncertain"


class FindingVerdict(str, Enum):
    CONFIRMED = "confirmed"      # Survived all gates
    KILLED = "killed"            # Failed Gate 1 (concrete refutation)
    DEMOTED = "demoted"          # Failed Gate 2/3/4 or speculative hit
    LEAD = "lead"                # Survived refutation but uncertain — track, don't report yet
    NEEDS_MANUAL = "needs_manual"  # Can't determine automatically


@dataclass
class GateEvaluation:
    gate: str  # refutation, reachability, trigger, impact
    result: GateResult
    reasoning: str = ""
    guard_trace: str = ""  # Exact code line or check that blocks the attack
    is_speculative: bool = False  # True if the objection is "probably" not "concretely"
    confidence: float = 1.0  # How confident is this gate evaluation?


@dataclass
class RefutationPass:
    pass_number: int
    model: str  # which model ran this pass
    started_at: str
    completed_at: str = ""
    verdict: FindingVerdict = FindingVerdict.NEEDS_MANUAL
    gate_results: List[GateEvaluation] = field(default_factory=list)
    kill_argument: str = ""  # The strongest argument against this finding
    survival_argument: str = ""  # Why it survived (if it did)
    affected_code: List[str] = field(default_factory=list)  # File:line references
    chain_parent: Optional[str] = None  # If this finding is part of a chain
    pass_hash: str = ""  # Hash of this pass for integrity

    def __post_init__(self):
        if not self.pass_hash:
            raw = f"{self.pass_number}:{self.model}:{self.started_at}"
            self.pass_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class RefutationRecord:
    finding_id: str
    target: str
    title: str = ""
    bug_class: str = ""
    severity: str = "info"
    endpoint: str = ""
    passes: List[RefutationPass] = field(default_factory=list)
    final_verdict: FindingVerdict = FindingVerdict.NEEDS_MANUAL
    total_passes: int = 0
    survived_passes: int = 0
    killed_passes: int = 0
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


# ---------------------------------------------------------------------------
# The adversarial prompt system
# ---------------------------------------------------------------------------

def build_adversarial_prompt(finding: Dict, gate: str = "all") -> str:
    """Construct the adversarial Red Team prompt across the 10 Red Team Attack Questions.

    The prompt is designed to be adversarial — the model wins if it kills the finding.
    """
    finding_text = json.dumps(finding, indent=2)

    gate_prompts = {
        "refutation": """
GATE 1 — RED TEAM ADVERSARIAL CHALLENGE (10 ATTACK QUESTIONS)

Your task: Attack this finding relentlessly. You win if you kill this finding.
Evaluate the finding strictly against the 10 Red Team Attack Questions:

1. Scope: Is the exact asset/function in scope?
2. Policy: Is this vulnerability class explicitly excluded?
3. Precondition: What does the attacker actually need?
4. Authentication: What credential/authorization is supposed to exist?
5. Path A: What is the legitimate intended flow?
6. Path B: What unauthorized flow was demonstrated?
7. Boundary: What security boundary is crossed?
8. Impact: What concrete capability does the attacker gain?
9. Alternative explanation: What is the strongest reasonable triager rebuttal?
10. Evidence: What observation defeats that rebuttal?

DEMONSTRATED VS INFERRED CLASSIFICATION:
Classify every claim as:
- Demonstrated (verified directly via executed PoC)
- Inferred (suggested by code/arch but unexecuted)
- Unproven (speculative)

THE RED TEAM RULE:
If the finding cannot survive the strongest plausible triager objection, output KILLED or DEMOTED.

Respond with:
1. KILLED: <strongest triager rebuttal + missing evidence> — OR —
2. CLEARED: <demonstrated evidence defeating all 10 questions> — OR —
3. DEMOTED: <claim is inferred/unproven — demote to OPEN LEAD>
""",

        "reachability": """
GATE 2 — REACHABILITY

Your task: Determine if the vulnerable state can actually exist in a live/deployed system.
You win if you prove the state is structurally impossible.

Rules:
- "Structurally impossible" = an enforced invariant in the code prevents the state from
  ever occurring (not just "unlikely" or "would require misconfiguration").
  → If you prove this, the finding is KILLED.
- "Requires privileged actions outside normal operation" = owner must misconfigure,
  multi-sig must collude, admin must make an unusual error.
  → The finding is DEMOTED (valid but lower severity).
- "Achievable through normal usage" = standard user actions, common admin patterns,
  typical deployment configurations.
  → The finding CLEARS this gate.

Respond with:
1. KILLED: <the invariant that makes this state impossible> — OR —
2. DEMOTED: <the privileged action required and why it's unlikely> — OR —
3. CLEARED: <how normal usage reaches this state>
""",

        "trigger": """
GATE 3 — TRIGGER

Your task: Determine if an unprivileged (or minimally privileged) actor can execute
the attack profitably.
You win if you prove the attack is economically irrational or restricted to trusted roles.

Rules:
- "Only a trusted role can trigger" = owner, admin, operator, multi-sig signer.
  → The finding is DEMOTED (not a critical exploit if it requires root).
- "Costs exceed extraction" = gas cost > profit, capital required > gain, time > value.
  → The finding is KILLED (not economically viable).
- "Unprivileged actor can trigger profitably" = any user, attacker with small capital,
  no special permissions needed.
  → The finding CLEARS this gate.

Respond with:
1. KILLED: <cost analysis showing attack is unprofitable> — OR —
2. DEMOTED: <which trusted role is required and why> — OR —
3. CLEARED: <how an unprivileged actor executes profitably>
""",

        "impact": """
GATE 4 — IMPACT

Your task: Determine if there is material harm to an identifiable victim.
You win if you prove the impact is self-harm only, dust-level, or non-compounding.

Rules:
- "Self-harm only" = attacker loses their own funds, no other victim.
  → The finding is KILLED.
- "Dust-level, non-compounding, no cascade" = impact is a few wei, a single log line,
  information already public, or cannot be repeated or scaled.
  → The finding is DEMOTED to low/informational.
- "Material loss to identifiable victim" = user funds drained, protocol shutdown,
  data breached, reputation destroyed, financial loss > $1K.
  → The finding CLEARS this gate and is CONFIRMED.

Respond with:
1. KILLED: <proof of self-harm only or no external victim> — OR —
2. DEMOTED: <why impact is below reportable threshold> — OR —
3. CLEARED: <specific victim, estimated loss, blast radius>
""",

        "all": """
FULL 4-GATE ADVERSARIAL REFUTATION

Your objective: KILL THIS FINDING. You win if you find a concrete reason it is not
a valid, reachable, triggerable, impactful vulnerability.

Evaluate each gate in order. Stop at the first KILLED gate.

GATE 1 — REFUTATION: Find a concrete guard that blocks the claimed attack step.
  Quote the exact line, config, or check. Speculation does NOT count.
  KILL if: concrete guard exists. CLEAR if: no concrete guard or only speculation.

GATE 2 — REACHABILITY: Can the vulnerable state exist in a live deployment?
  KILL if: structurally impossible (invariant prevents it).
  DEMOTE if: requires unusual privileged actions.
  CLEAR if: achievable through normal usage.

GATE 3 — TRIGGER: Can an unprivileged actor execute profitably?
  KILL if: costs exceed extraction.
  DEMOTE if: only trusted role can trigger.
  CLEAR if: unprivileged and profitable.

GATE 4 — IMPACT: Is there material harm to an identifiable victim?
  KILL if: self-harm only.
  DEMOTE if: dust-level, non-compounding.
  CLEAR if: material loss to identifiable victim.

For each gate, answer:
  RESULT: [KILLED|DEMOTED|CLEARED|UNCERTAIN]
  REASONING: [detailed explanation]
  GUARD_TRACE: [exact location if killed, empty if cleared]

At the end, give:
  FINAL_VERDICT: [CONFIRMED|KILLED|DEMOTED|LEAD|NEEDS_MANUAL]
  STRONGEST_KILL_ARGUMENT: [if any gate failed, the most damning point]
"""
    }

    prompt = f"""You are an adversarial security reviewer. Your objective is misaligned
with the finding below — you win if you PROVE it is NOT a valid vulnerability.

FINDING TO REFUTE:
{finding_text}

{gate_prompts.get(gate, gate_prompts['all'])}

Be rigorous. Be specific. Cite exact lines and mechanisms. Do not let a finding
through on "probably" or "likely" — only concrete guards kill.
"""
    return prompt


def build_chain_refutation_prompt(chain_findings: List[Dict]) -> str:
    """Build a refutation prompt for a chain of findings.

    A chain fails if ANY link in the chain fails a gate.
    """
    parts = []
    for i, f in enumerate(chain_findings):
        parts.append(f"--- Link {i+1}: {f.get('title', f.get('finding_id', '?'))} ---")
        parts.append(json.dumps(f, indent=2))

    chain_text = "\n".join(parts)

    return f"""You are an adversarial security reviewer evaluating an EXPLOIT CHAIN.

A chain is only as strong as its weakest link. If ANY link fails a gate,
the entire chain is broken. You win if you find the breaking link.

CHAIN TO REFUTE:
{chain_text}

For each link, evaluate:
  GATE 1 — Is there a concrete guard blocking this step?
  GATE 2 — Is this link's state reachable in a live deployment?

If any link is KILLED, the chain is broken.
If all links survive, the chain is CONFIRMED.

Respond with per-link analysis, then:
  CHAIN_VERDICT: [CONFIRMED|KILLED|DEMOTED]
  BREAKING_LINK: [link number that broke the chain, or NONE]
  BREAKING_REASON: [why the chain broke at that link]
"""


# ---------------------------------------------------------------------------
# Refutation Engine
# ---------------------------------------------------------------------------

class RefutationEngine:
    """Adversarial refutation for findings."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = REFUTATION_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)

    def _record_file(self, finding_id: str) -> Path:
        return self._dir / f"{finding_id}.json"

    def _load_record(self, finding_id: str) -> Optional[RefutationRecord]:
        f = self._record_file(finding_id)
        if f.exists():
            data = json.loads(f.read_text())
            record = RefutationRecord(**{
                k: v for k, v in data.items() if k != "passes"
            })
            record.passes = [RefutationPass(**p) for p in data.get("passes", [])]
            return record
        return None

    def _save_record(self, record: RefutationRecord):
        record.updated_at = datetime.now(timezone.utc).isoformat()
        data = asdict(record)
        data["passes"] = [asdict(p) for p in record.passes]
        self._record_file(record.finding_id).write_text(json.dumps(data, indent=2))

    def refute(self, finding: Dict, model: str = "haiku",
               passes: int = 1, chain_findings: List[Dict] = None) -> RefutationRecord:
        """Run adversarial refutation against a finding.

        Args:
            finding: The finding to refute (dict)
            model: Model to use for refutation (haiku/sonnet/opus)
            passes: Number of independent refutation passes (more = higher confidence)
            chain_findings: If this is a chain, the linked findings

        Returns:
            RefutationRecord with all pass results and final verdict
        """
        finding_id = finding.get("finding_id", hashlib.sha256(
            json.dumps(finding, sort_keys=True).encode()).hexdigest()[:16])

        # Load or create record
        record = self._load_record(finding_id)
        if record is None:
            record = RefutationRecord(
                finding_id=finding_id,
                target=self.target,
                title=finding.get("title", ""),
                bug_class=finding.get("bug_class", ""),
                severity=finding.get("severity", "info"),
                endpoint=finding.get("endpoint", ""),
            )

        for p in range(passes):
            pass_num = len(record.passes) + 1
            started = datetime.now(timezone.utc).isoformat()

            result = self._run_refutation_pass(
                finding, model, pass_num, chain_findings)

            result.started_at = started
            result.completed_at = datetime.now(timezone.utc).isoformat()
            record.passes.append(result)

        # Aggregate verdict
        record.total_passes = len(record.passes)
        record.survived_passes = sum(
            1 for p in record.passes if p.verdict == FindingVerdict.CONFIRMED)
        record.killed_passes = sum(
            1 for p in record.passes if p.verdict == FindingVerdict.KILLED)

        # Verdict rules:
        # - All passes CONFIRMED → CONFIRMED
        # - All passes KILLED → KILLED
        # - Any pass KILLED + some CONFIRMED → UNCERTAIN → needs manual
        # - All passes DEMOTED → DEMOTED
        # - Mixed DEMOTED + CONFIRMED → DEMOTED
        if record.survived_passes == record.total_passes:
            record.final_verdict = FindingVerdict.CONFIRMED
        elif record.killed_passes == record.total_passes:
            record.final_verdict = FindingVerdict.KILLED
        elif record.killed_passes > 0:
            record.final_verdict = FindingVerdict.LEAD
        elif all(p.verdict == FindingVerdict.DEMOTED for p in record.passes):
            record.final_verdict = FindingVerdict.DEMOTED
        else:
            record.final_verdict = FindingVerdict.LEAD

        self._save_record(record)
        return record

    def _run_refutation_pass(self, finding: Dict, model: str,
                              pass_num: int,
                              chain_findings: List[Dict] = None) -> RefutationPass:
        """Execute a single adversarial refutation pass.

        In a full implementation, this spawns a Claude Code agent with the
        adversarial prompt. For portability, it writes the prompt to a file
        that can be fed to any LLM, and parses structured output.

        Returns a RefutationPass with gate results.
        """
        rp = RefutationPass(
            pass_number=pass_num,
            model=model,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # Write the adversarial prompt for external execution
        prompt_file = self._dir / f"refute_{finding.get('finding_id', 'unknown')}_p{pass_num}.txt"

        if chain_findings:
            prompt = build_chain_refutation_prompt(chain_findings)
        else:
            prompt = build_adversarial_prompt(finding, "all")

        prompt_file.write_text(prompt)

        # Try automated refutation via Claude Code if available
        result = self._try_automated_refutation(prompt, model)
        if result:
            rp.gate_results = result.get("gates", [])
            rp.verdict = result.get("verdict", FindingVerdict.NEEDS_MANUAL)
            rp.kill_argument = result.get("kill_argument", "")
            rp.survival_argument = result.get("survival_argument", "")
            rp.affected_code = result.get("affected_code", [])
        else:
            # Manual refutation path — flag for human review
            rp.verdict = FindingVerdict.NEEDS_MANUAL
            rp.kill_argument = (
                f"Automated refutation unavailable. "
                f"Refutation prompt written to {prompt_file}. "
                f"Feed this to an LLM with adversarial instructions."
            )

        rp.completed_at = datetime.now(timezone.utc).isoformat()
        return rp

    def _try_automated_refutation(self, prompt: str, model: str) -> Optional[Dict]:
        """Attempt to run refutation via Claude CLI.

        Returns parsed gate results or None if unavailable.
        """
        try:
            result = subprocess.run(
                ["claude", "-p", prompt, "--model", model,
                 "--output-format", "json", "--max-tokens", "4096"],
                capture_output=True, text=True, timeout=300,
                env={**__import__('os').environ, "CLAUDE_CODE_EFFORT_LEVEL": "max"},
            )

            if result.returncode != 0:
                return None

            return self._parse_refutation_output(result.stdout)

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return None

    def _parse_refutation_output(self, output: str) -> Optional[Dict]:
        """Parse structured refutation output from the LLM response.

        Looks for the gate-by-gate format defined in the adversarial prompt.
        """
        gates = []
        verdict = FindingVerdict.NEEDS_MANUAL
        kill_arg = ""
        survive_arg = ""
        affected_code = []

        lines = output.splitlines()
        current_gate = None
        current_result = None
        current_reasoning = []

        for line in lines:
            line_stripped = line.strip()

            # Detect gate sections
            if line_stripped.upper().startswith("GATE 1") or "REFUTATION" in line_stripped.upper():
                if current_gate:
                    gates.append(GateEvaluation(
                        gate=current_gate,
                        result=self._parse_result(current_result),
                        reasoning="\n".join(current_reasoning),
                    ))
                current_gate = "refutation"
                current_result = None
                current_reasoning = []

            elif line_stripped.upper().startswith("GATE 2") or "REACHABILITY" in line_stripped.upper():
                if current_gate:
                    gates.append(GateEvaluation(
                        gate=current_gate,
                        result=self._parse_result(current_result),
                        reasoning="\n".join(current_reasoning),
                    ))
                current_gate = "reachability"
                current_result = None
                current_reasoning = []

            elif line_stripped.upper().startswith("GATE 3") or "TRIGGER" in line_stripped.upper():
                if current_gate:
                    gates.append(GateEvaluation(
                        gate=current_gate,
                        result=self._parse_result(current_result),
                        reasoning="\n".join(current_reasoning),
                    ))
                current_gate = "trigger"
                current_result = None
                current_reasoning = []

            elif line_stripped.upper().startswith("GATE 4") or "IMPACT" in line_stripped.upper():
                if current_gate:
                    gates.append(GateEvaluation(
                        gate=current_gate,
                        result=self._parse_result(current_result),
                        reasoning="\n".join(current_reasoning),
                    ))
                current_gate = "impact"
                current_result = None
                current_reasoning = []

            elif "RESULT:" in line_stripped.upper():
                current_result = line_stripped.split(":", 1)[-1].strip()

            elif "FINAL_VERDICT:" in line_stripped.upper():
                v = line_stripped.split(":", 1)[-1].strip().upper()
                verdict_map = {
                    "CONFIRMED": FindingVerdict.CONFIRMED,
                    "KILLED": FindingVerdict.KILLED,
                    "DEMOTED": FindingVerdict.DEMOTED,
                    "LEAD": FindingVerdict.LEAD,
                }
                verdict = verdict_map.get(v, FindingVerdict.NEEDS_MANUAL)

            elif "KILL_ARGUMENT:" in line_stripped.upper() or "STRONGEST_KILL" in line_stripped.upper():
                kill_arg = line_stripped.split(":", 1)[-1].strip()

            elif "SURVIVAL" in line_stripped.upper():
                survive_arg = line_stripped.split(":", 1)[-1].strip()

            elif line_stripped and current_gate:
                current_reasoning.append(line_stripped)

        # Save last gate
        if current_gate:
            gates.append(GateEvaluation(
                gate=current_gate,
                result=self._parse_result(current_result),
                reasoning="\n".join(current_reasoning),
            ))

        return {
            "gates": gates,
            "verdict": verdict,
            "kill_argument": kill_arg,
            "survival_argument": survive_arg,
            "affected_code": affected_code,
        }

    def _parse_result(self, result_str: Optional[str]) -> GateResult:
        if not result_str:
            return GateResult.UNCERTAIN
        r = result_str.upper().strip()
        if "KILL" in r:
            return GateResult.REJECTED
        if "CLEAR" in r or "PASS" in r:
            return GateResult.CLEARED
        if "DEMOTE" in r:
            return GateResult.DEMOTED
        return GateResult.UNCERTAIN

    def get_record(self, finding_id: str) -> Optional[RefutationRecord]:
        return self._load_record(finding_id)

    def get_all_records(self) -> List[RefutationRecord]:
        records = []
        for f in self._dir.glob("*.json"):
            finding_id = f.stem
            record = self._load_record(finding_id)
            if record:
                records.append(record)
        return records

    def get_survivors(self) -> List[RefutationRecord]:
        """Return findings that survived refutation."""
        return [r for r in self.get_all_records()
                if r.final_verdict == FindingVerdict.CONFIRMED]

    def generate_report(self) -> str:
        records = self.get_all_records()
        confirmed = [r for r in records if r.final_verdict == FindingVerdict.CONFIRMED]
        killed = [r for r in records if r.final_verdict == FindingVerdict.KILLED]
        demoted = [r for r in records if r.final_verdict == FindingVerdict.DEMOTED]
        leads = [r for r in records if r.final_verdict == FindingVerdict.LEAD]

        lines = [
            "=" * 72,
            f"  REFUTATION REPORT — {self.target}",
            "=" * 72,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            f"  Total findings refuted: {len(records)}",
            f"  Confirmed (survived):  {len(confirmed)}",
            f"  Killed (Gate 1 fail): {len(killed)}",
            f"  Demoted:              {len(demoted)}",
            f"  Leads (uncertain):    {len(leads)}",
            "=" * 72,
            "",
        ]

        if confirmed:
            lines.append("## CONFIRMED FINDINGS (survived all 4 gates)")
            lines.append("")
            for r in confirmed:
                lines.append(f"  [{r.severity.upper()}] {r.title}")
                lines.append(f"    Bug class: {r.bug_class}")
                lines.append(f"    Endpoint: {r.endpoint}")
                lines.append(f"    Passes survived: {r.survived_passes}/{r.total_passes}")
                lines.append("")

        if killed:
            lines.append("## KILLED FINDINGS (failed refutation)")
            lines.append("")
            for r in killed:
                lines.append(f"  {r.title}")
                last_pass = r.passes[-1] if r.passes else None
                if last_pass:
                    lines.append(f"    Kill argument: {last_pass.kill_argument[:200]}")
                lines.append("")

        if leads:
            lines.append("## LEADS (uncertain — track, don't report yet)")
            lines.append("")
            for r in leads:
                lines.append(f"  {r.title}")
                lines.append(f"    Survived: {r.survived_passes}, Killed: {r.killed_passes}")
                lines.append("")

        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Refutation Engine v3.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def refute_finding(target: str, finding: Dict, model: str = "haiku",
                   passes: int = 2) -> RefutationRecord:
    engine = RefutationEngine(target)
    return engine.refute(finding, model=model, passes=passes)


def refute_chain(target: str, chain_findings: List[Dict],
                 model: str = "haiku") -> RefutationRecord:
    """Refute an entire exploit chain. Chain breaks if any link fails."""
    engine = RefutationEngine(target)
    chain_id = "chain_" + hashlib.sha256(
        "".join(f.get("finding_id", "") for f in chain_findings).encode()
    ).hexdigest()[:16]

    composite = {
        "finding_id": chain_id,
        "title": f"Chain: {' → '.join(f.get('bug_class', '?') for f in chain_findings)}",
        "bug_class": "exploit_chain",
        "severity": "critical",
        "endpoint": ", ".join(f.get("endpoint", "") for f in chain_findings),
    }

    return engine.refute(composite, model=model, passes=1,
                         chain_findings=chain_findings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Adversarial Refutation Engine")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--finding-id", help="Single finding ID to refute")
    parser.add_argument("--finding-file", help="JSONL findings file to refute")
    parser.add_argument("--all", action="store_true", help="Refute all findings for target")
    parser.add_argument("--passes", type=int, default=2,
                        help="Number of refutation passes (default: 2)")
    parser.add_argument("--model", default="haiku",
                        choices=["haiku", "sonnet", "opus"],
                        help="Model for refutation (default: haiku)")
    parser.add_argument("--chain", action="store_true",
                        help="Refute as exploit chain (all findings must survive)")
    parser.add_argument("--survivors", action="store_true",
                        help="Show only findings that survived refutation")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    engine = RefutationEngine(args.target)

    findings = []
    if args.finding_file:
        raw = Path(args.finding_file).read_text()
        findings = [json.loads(l) for l in raw.splitlines() if l.strip()]
    elif args.all:
        try:
            from tools.state import get_findings
            findings = get_findings(args.target)
        except ImportError:
            print("[!] state module not available, use --finding-file")
            sys.exit(1)
    elif args.finding_id:
        try:
            from tools.state import get_findings
            all_findings = get_findings(args.target)
            findings = [f for f in all_findings
                        if f.get("finding_id") == args.finding_id]
        except ImportError:
            print("[!] finding not found, pass JSON via --finding-json")
            sys.exit(1)

    if not findings:
        print("[!] No findings to refute")
        sys.exit(1)

    print(f"[*] BountyForge Refutation Engine v3.0.0")
    print(f"[*] Target: {args.target}")
    print(f"[*] Findings to refute: {len(findings)}")
    print(f"[*] Passes per finding: {args.passes}")
    print(f"[*] Model: {args.model}")
    print()

    if args.chain:
        # Refute as a single chain
        record = refute_chain(args.target, findings, model=args.model)
        print(f"[*] Chain refutation complete")
        print(f"    Verdict: {record.final_verdict.value}")
        print(f"    Passes: {len(record.passes)}")
        if record.final_verdict == FindingVerdict.CONFIRMED:
            print("    ✅ Chain survived — all links confirmed")
        elif record.final_verdict == FindingVerdict.KILLED:
            print("    ❌ Chain broken")
        else:
            print("    ⚠️  Chain uncertain — manual review needed")
    else:
        records = []
        for finding in findings:
            record = engine.refute(finding, model=args.model, passes=args.passes)
            records.append(record)
            verdict_icon = {
                FindingVerdict.CONFIRMED: "✅",
                FindingVerdict.KILLED: "❌",
                FindingVerdict.DEMOTED: "⬇️",
                FindingVerdict.LEAD: "⚠️",
                FindingVerdict.NEEDS_MANUAL: "❓",
            }
            icon = verdict_icon.get(record.final_verdict, "❓")
            print(f"  {icon} [{record.final_verdict.value}] {record.title[:80]}")
            print(f"     survived: {record.survived_passes}/{record.total_passes} passes")

    if args.survivors:
        survivors = engine.get_survivors()
        print(f"\n[*] Survivors ({len(survivors)}):")
        for r in survivors:
            print(f"  ✅ [{r.severity.upper()}] {r.title}")

    if args.report:
        print("\n" + engine.generate_report())


if __name__ == "__main__":
    main()
