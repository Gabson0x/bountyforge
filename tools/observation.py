#!/usr/bin/env python3
"""
BountyForge Observation / Oracle Validation Layer v1.0.0

A raw HTTP response is never allowed to silently refute an experiment.

Before an experiment's hypothesis may be marked REFUTED, the candidate
response is compared against a control/baseline across every observable:
status code, body, headers, timing, redirects, and size. If the comparison
is ambiguous, or points at a DIFFERENT EXECUTION PATH (e.g., a 404 whose
timing is wildly different from the baseline 404 — the classic time-based
blind-injection signature), the observation is classified UNKNOWN and a
follow-up experiment is generated.

Design invariant:
  - The LLM may flag ambiguity, rank it, and request follow-ups.
  - DETERMINISTIC CODE OWNS THE FINAL OBSERVATION STATE.
  - Every rule evaluation is preserved in the reasoning chain, and the
    original raw observation is preserved verbatim in provenance.

No detection rules live here. This layer only decides whether an observation
may refute, confirm, or remains ambiguous against a control.

Usage:
  from tools.observation import OracleValidator, HttpObservation, ObservationState

  validator = OracleValidator()
  record = validator.validate(candidate, control,
                              url="...", method="GET", bug_class="sqli",
                              probe_label="SQLi: tick probe")
  if record.state == ObservationState.UNKNOWN:
      record.follow_up  # deterministic follow-up experiment spec
"""

import json
import os
import hashlib
import difflib
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = "observation-oracle-v1"

OBSERVATIONS_ROOT = ROOT / "state" / "observations"


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class ObservationState(str, Enum):
    SIGNAL = "signal"    # Deterministic evidence the experiment changed behavior
    REFUTED = "refuted"  # Candidate matched control across all observables
    UNKNOWN = "unknown"  # Ambiguous or a different execution path — follow-up required
    ERROR = "error"      # Transport/parse failure — nothing to conclude


class FollowUpKind(str, Enum):
    TIMING_CONTROL = "timing_control"
    STATUS_PROBE = "status_probe"
    BODY_DIFF_PROBE = "body_diff_probe"
    REDIRECT_PROBE = "redirect_probe"
    GENERIC_RETRY = "generic_retry"


# ---------------------------------------------------------------------------
# Observation primitives
# ---------------------------------------------------------------------------

@dataclass
class HttpObservation:
    """A single captured HTTP response (candidate or control).

    `body` and `headers` are stored verbatim; `body_hash` is derived so the
    original observation can always be reproduced from provenance.
    """
    status: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    timing_seconds: float = 0.0
    size_bytes: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    error: str = ""
    captured_at: str = ""

    def __post_init__(self):
        if not self.captured_at:
            self.captured_at = datetime.now(timezone.utc).isoformat()

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body.encode()).hexdigest()

    def is_transport_error(self) -> bool:
        return self.status <= 0 or bool(self.error)


@dataclass
class ComparisonMetrics:
    """Structural deltas between candidate and control."""
    status_delta: str = ""          # e.g. "404 -> 404", "200 -> 500"
    body_identical: bool = False
    body_similarity: float = 0.0    # difflib ratio 0..1
    timing_delta: float = 0.0       # candidate - control (seconds)
    timing_ratio: float = 1.0       # candidate / control (guarded)
    size_delta: int = 0             # candidate - control (bytes)
    header_additions: List[str] = field(default_factory=list)
    header_removals: List[str] = field(default_factory=list)
    redirect_delta: str = ""        # description of redirect chain divergence


@dataclass
class ReasoningStep:
    """One deterministic rule evaluation, appended in execution order."""
    rule: str
    outcome: str    # fired | not_fired | decisive | advisory_only
    detail: str = ""
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()


@dataclass
class RequestSpec:
    """A single request in a follow-up experiment."""
    role: str               # candidate | control
    method: str
    url: str
    payload: str = ""
    note: str = ""
    runs: int = 1


@dataclass
class FollowUpExperiment:
    """A follow-up experiment generated when an observation is UNKNOWN.

    `acceptance` is a list of deterministic criteria — code evaluates the
    follow-up, never the LLM.
    """
    kind: FollowUpKind
    follow_up_id: str = ""
    purpose: str = ""
    requests: List[RequestSpec] = field(default_factory=list)
    acceptance: List[str] = field(default_factory=list)
    generated_by: str = "deterministic"  # deterministic | llm_requested
    llm_rationale: str = ""
    status: str = "pending"     # pending | executed | resolved
    result_state: str = ""      # final ObservationState after execution
    created_at: str = ""

    def __post_init__(self):
        if not self.follow_up_id:
            raw = f"{self.kind.value}:{self.purpose}:{datetime.now(timezone.utc).isoformat()}"
            self.follow_up_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ObservationRecord:
    """Full validation record: candidate vs control, deterministic state,
    reasoning chain, follow-up, and verbatim provenance."""
    observation_id: str = ""
    experiment_id: str = ""
    target: str = ""
    url: str = ""               # candidate (probe) URL
    control_url: str = ""       # baseline URL the control was fetched from
    method: str = ""
    bug_class: str = ""
    probe_label: str = ""
    candidate: HttpObservation = field(default_factory=HttpObservation)
    control: HttpObservation = field(default_factory=HttpObservation)
    metrics: ComparisonMetrics = field(default_factory=ComparisonMetrics)
    state: ObservationState = ObservationState.UNKNOWN
    decisive_rule: str = ""
    reasoning_chain: List[ReasoningStep] = field(default_factory=list)
    llm_note: str = ""              # advisory only — never sets state
    llm_priority_hint: int = 0
    follow_up: Optional[FollowUpExperiment] = None
    provenance: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    record_hash: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.observation_id:
            raw = f"{self.experiment_id}|{self.url}|{self.method}|{self.candidate.body_hash}"
            self.observation_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.record_hash:
            self.record_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Canonical hash of the immutable record content (provenance included)."""
        payload = {
            "observation_id": self.observation_id,
            "experiment_id": self.experiment_id,
            "url": self.url,
            "control_url": self.control_url,
            "method": self.method,
            "bug_class": self.bug_class,
            "candidate": asdict(self.candidate),
            "control": asdict(self.control),
            "metrics": asdict(self.metrics),
            "state": self.state.value,
            "decisive_rule": self.decisive_rule,
            "reasoning_chain": [asdict(s) for s in self.reasoning_chain],
            "llm_note": self.llm_note,
            "llm_priority_hint": self.llm_priority_hint,
            "follow_up": asdict(self.follow_up) if self.follow_up else None,
            "provenance": self.provenance,
        }
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "observation_id": self.observation_id,
            "experiment_id": self.experiment_id,
            "target": self.target,
            "url": self.url,
            "control_url": self.control_url,
            "method": self.method,
            "bug_class": self.bug_class,
            "probe_label": self.probe_label,
            "candidate": asdict(self.candidate),
            "control": asdict(self.control),
            "metrics": asdict(self.metrics),
            "state": self.state.value,
            "decisive_rule": self.decisive_rule,
            "reasoning_chain": [asdict(s) for s in self.reasoning_chain],
            "llm_note": self.llm_note,
            "llm_priority_hint": self.llm_priority_hint,
            "follow_up": asdict(self.follow_up) if self.follow_up else None,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "record_hash": self.record_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservationRecord":
        def _obs(d: Dict[str, Any]) -> HttpObservation:
            return HttpObservation(**d)

        def _metrics(d: Dict[str, Any]) -> ComparisonMetrics:
            return ComparisonMetrics(**d)

        def _chain(d: List[Dict[str, Any]]) -> List[ReasoningStep]:
            return [ReasoningStep(**s) for s in d]

        def _fu(d: Optional[Dict[str, Any]]) -> Optional[FollowUpExperiment]:
            if not d:
                return None
            fu = d.copy()
            fu["kind"] = FollowUpKind(fu["kind"])
            fu["requests"] = [RequestSpec(**r) for r in fu.get("requests", [])]
            return FollowUpExperiment(**fu)

        record = cls(
            observation_id=data["observation_id"],
            experiment_id=data["experiment_id"],
            target=data.get("target", ""),
            url=data.get("url", ""),
            control_url=data.get("control_url", ""),
            method=data.get("method", ""),
            bug_class=data.get("bug_class", ""),
            probe_label=data.get("probe_label", ""),
            candidate=_obs(data["candidate"]),
            control=_obs(data["control"]),
            metrics=_metrics(data["metrics"]),
            state=ObservationState(data.get("state", "unknown")),
            decisive_rule=data.get("decisive_rule", ""),
            reasoning_chain=_chain(data.get("reasoning_chain", [])),
            llm_note=data.get("llm_note", ""),
            llm_priority_hint=data.get("llm_priority_hint", 0),
            follow_up=_fu(data.get("follow_up")),
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            record_hash=data.get("record_hash", ""),
        )
        return record

    def verify_hash(self) -> bool:
        """Tamper-evidence: recompute and compare the record hash."""
        return self.compute_hash() == self.record_hash


# ---------------------------------------------------------------------------
# Deterministic oracle rules
# ---------------------------------------------------------------------------

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def compute_metrics(candidate: HttpObservation,
                    control: HttpObservation) -> ComparisonMetrics:
    """Structural deltas between candidate and control."""
    m = ComparisonMetrics()
    m.status_delta = f"{control.status} -> {candidate.status}"

    if candidate.body == control.body:
        m.body_identical = True
        m.body_similarity = 1.0
    elif not candidate.body and not control.body:
        m.body_identical = True
        m.body_similarity = 1.0
    else:
        # Cap similarity comparison — full-body diff on huge responses is noise.
        sample_a = candidate.body[:200_000]
        sample_b = control.body[:200_000]
        m.body_similarity = round(
            difflib.SequenceMatcher(None, sample_a, sample_b).ratio(), 4)

    m.timing_delta = round(candidate.timing_seconds - control.timing_seconds, 4)
    if control.timing_seconds > 0.05:
        m.timing_ratio = round(candidate.timing_seconds / control.timing_seconds, 3)
    elif candidate.timing_seconds > 0:
        m.timing_ratio = 999.0
    else:
        m.timing_ratio = 1.0

    m.size_delta = candidate.size_bytes - control.size_bytes

    cand_h = set(candidate.headers.keys())
    ctrl_h = set(control.headers.keys())
    m.header_additions = sorted(cand_h - ctrl_h)
    m.header_removals = sorted(ctrl_h - cand_h)

    if tuple(candidate.redirect_chain) != tuple(control.redirect_chain):
        m.redirect_delta = (
            f"{tuple(control.redirect_chain)} -> {tuple(candidate.redirect_chain)}")
    return m


# ---------------------------------------------------------------------------
# Oracle Validator — deterministic owner of observation state
# ---------------------------------------------------------------------------

class OracleValidator:
    """Compares a candidate response against a control and assigns the
    observation state using only deterministic rules.

    Rule ordering is load-bearing: the timing rule fires BEFORE the
    control-match rule, so a 404 that matches baseline in status/body but
    carries a wildly different timing is UNKNOWN, never REFUTED.
    """

    def __init__(self,
                 timing_ratio_threshold: float = 3.0,
                 timing_abs_threshold: float = 0.5,
                 similarity_threshold: float = 0.98,
                 body_min_bytes: int = 50):
        self.timing_ratio_threshold = timing_ratio_threshold
        self.timing_abs_threshold = timing_abs_threshold
        self.similarity_threshold = similarity_threshold
        self.body_min_bytes = body_min_bytes

    # -- public API ---------------------------------------------------------

    def validate(self,
                 candidate: HttpObservation,
                 control: HttpObservation,
                 url: str = "",
                 control_url: str = "",
                 method: str = "",
                 bug_class: str = "",
                 probe_label: str = "",
                 experiment_id: str = "",
                 target: str = "",
                 llm_note: str = "",
                 llm_priority_hint: int = 0) -> ObservationRecord:
        """Validate a candidate response against a control.

        Deterministic rules own the final state. An LLM note (if supplied)
        is preserved as advisory commentary and never modifies the verdict.
        """
        metrics = compute_metrics(candidate, control)
        chain: List[ReasoningStep] = []

        if not experiment_id:
            experiment_id = _sha(f"{url}|{method}|{probe_label}")[:16]
        if not control_url:
            control_url = url

        record = ObservationRecord(
            experiment_id=experiment_id,
            url=url,
            control_url=control_url,
            method=method,
            bug_class=bug_class,
            probe_label=probe_label,
            target=target,
            candidate=candidate,
            control=control,
            metrics=metrics,
        )

        # Provenance: preserve the original observation verbatim.
        record.provenance = {
            "schema": SCHEMA_VERSION,
            "preserved_at": datetime.now(timezone.utc).isoformat(),
            "request": {
                "url": url,
                "control_url": control_url,
                "method": method,
                "probe_label": probe_label,
                "experiment_id": experiment_id,
            },
            "candidate_raw": asdict(candidate),
            "control_raw": asdict(control),
        }

        # Fixed rule order — every rule is evaluated and recorded; the first
        # decisive outcome owns the state.
        rules = [
            ("r1_transport_error", self._r1_transport_error),
            ("r4_timing_divergence", self._r4_timing_divergence),
            ("r6_redirect_divergence", self._r6_redirect_divergence),
            ("r3_status_divergence", self._r3_status_divergence),
            ("r5_body_divergence", self._r5_body_divergence),
            ("r7_header_divergence", self._r7_header_divergence),
            ("r2_control_match", self._r2_control_match),
            ("r8_fallback", self._r8_fallback),
        ]

        for name, rule in rules:
            outcome = rule(record)
            if outcome is None:
                chain.append(ReasoningStep(rule=name, outcome="not_fired",
                                           detail="no divergence detected"))
                continue
            state, detail, follow_up = outcome
            record.state = state
            record.decisive_rule = name
            chain.append(ReasoningStep(rule=name, outcome="decisive", detail=detail))
            if follow_up is not None:
                record.follow_up = follow_up
            break

        if llm_note:
            record.llm_note = llm_note
            record.llm_priority_hint = llm_priority_hint
            chain.append(ReasoningStep(
                rule="llm_commentary",
                outcome="advisory_only",
                detail=(f"LLM note preserved verbatim; priority hint {llm_priority_hint}. "
                        f"State remains owned by deterministic rules (was not modified by the note). "
                        f"NOTE: {llm_note[:400]}"),
            ))

        record.reasoning_chain = chain
        record.updated_at = datetime.now(timezone.utc).isoformat()
        record.record_hash = record.compute_hash()
        return record

    # -- deterministic rules ------------------------------------------------

    def _r1_transport_error(self, record: ObservationRecord):
        """Transport/parse failure — nothing to conclude."""
        if record.candidate.is_transport_error():
            detail = (f"candidate transport error: status={record.candidate.status}, "
                      f"error={record.candidate.error[:200]}")
            return (ObservationState.ERROR, detail, None)
        return None

    def _r4_timing_divergence(self, record: ObservationRecord):
        """Timing delta beyond thresholds = a DIFFERENT EXECUTION PATH.

        Fires before the control-match rule: even a response identical in
        status/body (e.g., the canonical 404 page) must not be treated as a
        refutation when the payload took seconds where the baseline took
        milliseconds — the classic time-based blind-injection signal.
        """
        m = record.metrics
        slow = (m.timing_delta >= self.timing_abs_threshold
                and m.timing_ratio >= self.timing_ratio_threshold)
        if not slow:
            return None
        detail = (
            f"candidate timing {record.candidate.timing_seconds}s vs control "
            f"{record.control.timing_seconds}s (delta {m.timing_delta}s, "
            f"ratio {m.timing_ratio}x) — status/body equality does NOT refute; "
            f"the payload appears to execute a different code path.")
        return (ObservationState.UNKNOWN, detail,
                self._follow_up_timing(record))

    def _r3_status_divergence(self, record: ObservationRecord):
        """Status code changed vs control."""
        c_stat = record.candidate.status
        b_stat = record.control.status
        if c_stat == b_stat:
            return None

        # Baseline healthy, candidate 5xx — server crashed on the payload.
        if b_stat < 400 and c_stat >= 500:
            detail = (f"status {record.metrics.status_delta}: baseline healthy, "
                      f"candidate produced a server-side error on the payload.")
            return (ObservationState.SIGNAL, detail, None)

        # Candidate 404/403 while baseline is not — routing/filtering changed,
        # i.e. a different execution path. Not a refutation.
        if c_stat in (404, 403) and b_stat not in (404, 403):
            detail = (f"status {record.metrics.status_delta}: payload changed "
                      f"routing/filtering — the request hit a different "
                      f"execution path than the control.")
            return (ObservationState.UNKNOWN, detail,
                    self._follow_up_status(record))

        # Any other status divergence — ambiguous by definition.
        detail = (f"status {record.metrics.status_delta}: candidate diverged "
                  f"from control; execution path difference cannot be excluded.")
        return (ObservationState.UNKNOWN, detail,
                self._follow_up_status(record))

    def _r6_redirect_divergence(self, record: ObservationRecord):
        """Redirect chain differs from control."""
        cand = record.candidate.redirect_chain
        ctrl = record.control.redirect_chain
        if tuple(cand) == tuple(ctrl):
            return None

        # Redirect target echoes attacker-controlled content (open-redirect
        # class: the injected value lands in Location).
        injected = False
        for loc in cand:
            if "evil" in loc.lower() or _url_injected(loc, record.url):
                injected = True
        if injected:
            detail = (f"redirect divergence {record.metrics.redirect_delta}: "
                      f"candidate Location carries the attacker-controlled value.")
            return (ObservationState.SIGNAL, detail, None)

        detail = (f"redirect divergence {record.metrics.redirect_delta}: "
                  f"candidate followed a different path than control.")
        return (ObservationState.UNKNOWN, detail,
                self._follow_up_redirect(record))

    def _r5_body_divergence(self, record: ObservationRecord):
        """Same status/timing but body materially different."""
        m = record.metrics
        if m.body_identical:
            return None
        meaningful = (
            len(record.candidate.body) >= self.body_min_bytes
            or len(record.control.body) >= self.body_min_bytes
        )
        if meaningful and m.body_similarity < self.similarity_threshold:
            detail = (f"same status ({record.candidate.status}) but body diverges "
                      f"(similarity {m.body_similarity}, size {record.control.size_bytes} "
                      f"-> {record.candidate.size_bytes}): the payload changed the "
                      f"response content — ambiguous, not a refutation.")
            return (ObservationState.UNKNOWN, detail,
                    self._follow_up_body(record))
        return None

    def _r7_header_divergence(self, record: ObservationRecord):
        """Material header additions in the candidate (e.g. Set-Cookie,
        error markers) — observable side effect, so not a clean refutation."""
        if not record.metrics.header_additions:
            return None
        detail = (f"candidate introduced headers: "
                  f"{', '.join(record.metrics.header_additions)} "
                  f"(not present in control).")
        return (ObservationState.UNKNOWN, detail,
                self._follow_up_retry(record))

    def _r2_control_match(self, record: ObservationRecord):
        """Candidate matches control across every observable → REFUTED."""
        m = record.metrics
        timing_ok = (abs(m.timing_delta) < self.timing_abs_threshold
                     and m.timing_ratio < self.timing_ratio_threshold)
        status_ok = record.candidate.status == record.control.status
        body_ok = m.body_identical
        redirect_ok = (tuple(record.candidate.redirect_chain)
                       == tuple(record.control.redirect_chain))
        header_ok = not m.header_additions
        if status_ok and body_ok and timing_ok and redirect_ok and header_ok:
            detail = (f"candidate reproduced control behavior across status, body, "
                      f"timing, redirects, and headers — the payload produced no "
                      f"observable delta. Experiment refuted.")
            return (ObservationState.REFUTED, detail, None)
        return None

    def _r8_fallback(self, record: ObservationRecord):
        """Default guard: never silently refute an unexplained divergence."""
        m = record.metrics
        status_ok = record.candidate.status == record.control.status
        body_ok = m.body_identical
        redirect_ok = (tuple(record.candidate.redirect_chain)
                       == tuple(record.control.redirect_chain))
        if status_ok and body_ok and redirect_ok:
            detail = (f"residual deltas below thresholds; no observable delta "
                      f"worth pursuing. Experiment refuted.")
            return (ObservationState.REFUTED, detail, None)
        detail = ("unexplained divergence from control — cannot conclude "
                  "refutation deterministically.")
        return (ObservationState.UNKNOWN, detail,
                self._follow_up_retry(record))

    # -- follow-up experiment generation (deterministic) --------------------

    def _follow_up_timing(self, record: ObservationRecord) -> FollowUpExperiment:
        return FollowUpExperiment(
            kind=FollowUpKind.TIMING_CONTROL,
            purpose=("Resolve timing divergence: repeat candidate and control "
                     "with alternating order to measure median timing deltas."),
            requests=[
                RequestSpec(role="control", method=record.method,
                            url=record.control_url,
                            note="baseline request (no payload)", runs=3),
                RequestSpec(role="candidate", method=record.method, url=record.url,
                            note=record.probe_label, runs=3),
            ],
            acceptance=[
                f"median(candidate timing) >= median(control timing) + "
                f"{max(self.timing_abs_threshold, 0.5)}s across 3 runs each",
                "divergence reproduces in at least 2 of 3 candidate runs",
            ],
        )

    def _follow_up_status(self, record: ObservationRecord) -> FollowUpExperiment:
        return FollowUpExperiment(
            kind=FollowUpKind.STATUS_PROBE,
            purpose=("Resolve status divergence: replay the baseline URL and the "
                     "payload URL to see whether the payload itself caused the "
                     "status change or the endpoint always behaves that way."),
            requests=[
                RequestSpec(role="control", method=record.method,
                            url=record.control_url,
                            note="baseline request (no payload)", runs=1),
                RequestSpec(role="candidate", method=record.method, url=record.url,
                            payload=record.probe_label,
                            note="payload replay", runs=1),
            ],
            acceptance=[
                "fresh candidate status matches fresh control status -> "
                "endpoint behavior, treat as REFUTED",
                "fresh candidate status diverges again -> payload-driven, keep UNKNOWN",
            ],
        )

    def _follow_up_body(self, record: ObservationRecord) -> FollowUpExperiment:
        return FollowUpExperiment(
            kind=FollowUpKind.BODY_DIFF_PROBE,
            purpose=("Resolve body divergence: replay the candidate 3 times to "
                     "check the delta is reproducible and not transient noise."),
            requests=[
                RequestSpec(role="control", method=record.method,
                            url=record.control_url,
                            note="baseline request (no payload)", runs=1),
                RequestSpec(role="candidate", method=record.method, url=record.url,
                            note=record.probe_label, runs=3),
            ],
            acceptance=[
                "body divergence reproduces in at least 2 of 3 candidate runs",
                "divergence is not caused by session rotation / WAF jitter",
            ],
        )

    def _follow_up_redirect(self, record: ObservationRecord) -> FollowUpExperiment:
        return FollowUpExperiment(
            kind=FollowUpKind.REDIRECT_PROBE,
            purpose=("Resolve redirect divergence: toggle the injected parameter "
                     "and verify Location follows the attacker-controlled value."),
            requests=[
                RequestSpec(role="control", method=record.method,
                            url=record.control_url,
                            note="baseline request (no payload)", runs=1),
                RequestSpec(role="candidate", method=record.method, url=record.url,
                            payload=record.probe_label,
                            note="payload replay", runs=1),
            ],
            acceptance=[
                "candidate Location varies with the injected parameter value",
            ],
        )

    def _follow_up_retry(self, record: ObservationRecord) -> FollowUpExperiment:
        return FollowUpExperiment(
            kind=FollowUpKind.GENERIC_RETRY,
            purpose=("Resolve ambiguous delta: replay candidate and control "
                     "3 times and compare medians across all observables."),
            requests=[
                RequestSpec(role="control", method=record.method,
                            url=record.control_url,
                            note="baseline request (no payload)", runs=3),
                RequestSpec(role="candidate", method=record.method, url=record.url,
                            note=record.probe_label, runs=3),
            ],
            acceptance=[
                "all three candidate runs match control across status/body/timing "
                "-> REFUTED",
                "any candidate run diverges reproducibly -> keep UNKNOWN / escalate",
            ],
        )

    # -- LLM advisory interface ---------------------------------------------

    def attach_llm_note(self, record: ObservationRecord, note: str,
                        priority_hint: int = 0,
                        requested_follow_up: bool = False) -> ObservationRecord:
        """Attach LLM commentary.

        The note may flag ambiguity, rank priority, or request a follow-up —
        it can NEVER flip the deterministic state. If a follow-up is requested
        and none exists, a deterministic GENERIC_RETRY spec is generated.
        """
        record.llm_note = note
        record.llm_priority_hint = priority_hint
        record.reasoning_chain.append(ReasoningStep(
            rule="llm_commentary",
            outcome="advisory_only",
            detail=(f"LLM requested follow-up={requested_follow_up}; note: "
                    f"{note[:400]}. Deterministic state '{record.state.value}' "
                    f"was NOT modified."),
        ))
        if requested_follow_up and record.follow_up is None:
            record.follow_up = self._follow_up_retry(record)
            record.follow_up.generated_by = "llm_requested"
        record.updated_at = datetime.now(timezone.utc).isoformat()
        record.record_hash = record.compute_hash()
        return record


def _url_injected(loc: str, url: str) -> bool:
    """True if the Location target mirrors a parameter value from the probe URL."""
    try:
        import urllib.parse
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for values in qs.values():
            for v in values:
                if v and v in loc:
                    return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Persistence (append-only JSONL, mirrors tools/state conventions)
# ---------------------------------------------------------------------------

def atomic_append(path: Path, line: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(line.rstrip("\n") + "\n")
        f.flush()
        os.fsync(f.fileno())


def _obs_file(target: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
    return OBSERVATIONS_ROOT / f"{safe}.jsonl"


def save_observation(target: str, record: ObservationRecord):
    """Persist an observation record (append-only)."""
    atomic_append(_obs_file(target), json.dumps(record.to_dict()))


def load_observations(target: str) -> List[ObservationRecord]:
    """Load all observation records for a target."""
    f = _obs_file(target)
    if not f.exists():
        return []
    records = []
    for line in f.read_text().splitlines():
        if line.strip():
            try:
                records.append(ObservationRecord.from_dict(json.loads(line)))
            except Exception:
                continue  # skip corrupt lines, never break the loader
    return records


def get_unknown_observations(target: str) -> List[ObservationRecord]:
    return [r for r in load_observations(target)
            if r.state == ObservationState.UNKNOWN]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Observation/Oracle Validation Layer")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--summary", action="store_true",
                        help="Summarize persisted observation states")
    args = parser.parse_args()

    records = load_observations(args.target)
    counts = {}
    for r in records:
        counts[r.state.value] = counts.get(r.state.value, 0) + 1

    print(f"[*] Observation records for {args.target}: {len(records)}")
    for state, n in sorted(counts.items()):
        print(f"    {state}: {n}")
    if args.summary:
        print()
        for r in records:
            fu = r.follow_up.kind.value if r.follow_up else "none"
            print(f"  [{r.state.value}] {r.experiment_id[:12]} {r.url} "
                  f"({r.decisive_rule}, follow-up: {fu})")


if __name__ == "__main__":
    main()
