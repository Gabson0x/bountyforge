#!/usr/bin/env python3
"""
Regression tests for the BountyForge Observation / Oracle Validation layer.

Run:  python3 -m unittest discover -s tests -v

Guards the core invariant:
  An HTTP response must NOT automatically constitute refutation. Observations
  are only REFUTED when the candidate matches the control/baseline across
  status, body, headers, timing, redirects, and size. Ambiguous observations
  — or ones pointing at a different execution path — are UNKNOWN and generate
  a deterministic follow-up experiment. LLM commentary is advisory only;
  deterministic code owns the final observation state.

Headline regression: the 404-with-significantly-different-timing case.
A naive refutation path sees "404 == baseline 404" and kills the experiment.
The payload actually executed a different code path (time-based blind
injection): identical 404 status/body, but 6.2s vs 0.08s. That must be
UNKNOWN with a TIMING_CONTROL follow-up — never REFUTED.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.observation import (
    OracleValidator, HttpObservation, ObservationRecord,
    ObservationState, FollowUpKind,
    save_observation, load_observations,
)

NOT_FOUND_BODY = "<html><body><h1>Not Found</h1></body></html>"
SERVING_BODY = "<html><body><h1>Dashboard</h1><p>welcome</p></body></html>"

NGINX_HEADERS = {"content-type": "text/html; charset=utf-8", "server": "nginx"}


def make_obs(status: int = 200, body: str = SERVING_BODY,
             timing: float = 0.1, headers: dict = None,
             redirects: list = None, size: int = 0) -> HttpObservation:
    h = dict(headers) if headers is not None else dict(NGINX_HEADERS)
    return HttpObservation(status=status, body=body, timing_seconds=timing,
                           headers=h, redirect_chain=list(redirects or []),
                           size_bytes=size or len(body))


class TestOracleValidationBasics(unittest.TestCase):

    def setUp(self):
        self.v = OracleValidator()

    def test_exact_control_match_refutes(self):
        cand = make_obs()
        ctrl = make_obs()
        r = self.v.validate(cand, ctrl, url="https://t/app", method="GET",
                            bug_class="sqli", probe_label="probe", target="t")
        self.assertEqual(r.state, ObservationState.REFUTED)
        self.assertEqual(r.decisive_rule, "r2_control_match")

    def test_404_matching_baseline_refutes(self):
        cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.09)
        ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)
        r = self.v.validate(cand, ctrl, url="https://t/missing?id=1'",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.REFUTED)

    def test_404_matching_baseline_with_sub_threshold_timing_refutes(self):
        cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.15)
        ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)
        r = self.v.validate(cand, ctrl, url="https://t/missing", method="GET",
                            bug_class="sqli", probe_label="probe", target="t")
        self.assertEqual(r.state, ObservationState.REFUTED)

    def test_status_500_from_healthy_baseline_is_signal(self):
        cand = make_obs(status=500, body="internal server error", timing=0.2)
        ctrl = make_obs(status=200, timing=0.1)
        r = self.v.validate(cand, ctrl, url="https://t/app?id=1'",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.SIGNAL)
        self.assertEqual(r.decisive_rule, "r3_status_divergence")
        self.assertIsNone(r.follow_up)

    def test_transport_error_is_error(self):
        cand = HttpObservation(status=-1, error="connection reset")
        ctrl = make_obs()
        r = self.v.validate(cand, ctrl, url="https://t/app", method="GET",
                            bug_class="sqli", probe_label="probe", target="t")
        self.assertEqual(r.state, ObservationState.ERROR)
        self.assertEqual(r.decisive_rule, "r1_transport_error")


class TestHeadlineRegression404Timing(unittest.TestCase):
    """REGRESSION: the 404-with-significantly-different-timing case.

    Previously, a refutation path comparing only status+body would see
    "404 == 404, same body" and kill the experiment. The payload may have
    executed a different code path (time-based blind injection) — the timing
    delta is the only observable that exposes it. The timing rule must fire
    BEFORE the control-match rule.
    """

    def setUp(self):
        self.v = OracleValidator()
        self.cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=6.2)
        self.ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)

    def test_404_with_significantly_different_timing_is_unknown(self):
        r = self.v.validate(self.cand, self.ctrl,
                            url="https://t/app?id=1 AND SLEEP(5)--",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe", target="t")
        self.assertEqual(r.state, ObservationState.UNKNOWN,
                         "identical 404 status/body with wildly different "
                         "timing must NOT be refuted")
        self.assertEqual(r.decisive_rule, "r4_timing_divergence")

    def test_404_timing_divergence_generates_follow_up(self):
        r = self.v.validate(self.cand, self.ctrl,
                            url="https://t/app?id=1 AND SLEEP(5)--",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe", target="t")
        self.assertIsNotNone(r.follow_up)
        self.assertEqual(r.follow_up.kind, FollowUpKind.TIMING_CONTROL)
        self.assertEqual(r.follow_up.generated_by, "deterministic")

    def test_timing_follow_up_has_candidate_and_control_roles(self):
        r = self.v.validate(self.cand, self.ctrl,
                            url="https://t/app?id=1 AND SLEEP(5)--",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe", target="t")
        roles = [req.role for req in r.follow_up.requests]
        self.assertIn("candidate", roles)
        self.assertIn("control", roles)
        self.assertTrue(all(req.runs >= 3 for req in r.follow_up.requests),
                        "timing studies need repeated runs for median stability")

    def test_timing_follow_up_acceptance_is_deterministic(self):
        r = self.v.validate(self.cand, self.ctrl,
                            url="https://t/app?id=1 AND SLEEP(5)--",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe", target="t")
        self.assertTrue(r.follow_up.acceptance,
                        "acceptance criteria must be machine-checkable")
        joined = " ".join(r.follow_up.acceptance).lower()
        self.assertIn("median", joined)

    def test_timing_rule_fires_before_control_match_rule(self):
        # The reasoning chain must show the timing rule as decisive, with the
        # control-match rule never even fired (refutation blocked).
        r = self.v.validate(self.cand, self.ctrl,
                            url="https://t/app?id=1 AND SLEEP(5)--",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe", target="t")
        outcomes = {s.rule: s.outcome for s in r.reasoning_chain}
        self.assertEqual(outcomes.get("r4_timing_divergence"), "decisive")
        self.assertNotEqual(outcomes.get("r2_control_match"), "decisive")

    def test_follow_up_control_targets_baseline_url(self):
        # The follow-up's control requests must hit the payload-free baseline
        # URL — otherwise the "control" runs execute the payload and the
        # timing comparison is meaningless.
        r = self.v.validate(
            self.cand, self.ctrl,
            url="https://t/app?id=1 AND SLEEP(5)--",
            control_url="https://t/app",
            method="GET", bug_class="sqli",
            probe_label="SQLi: time-based probe", target="t")
        control_reqs = [req for req in r.follow_up.requests
                        if req.role == "control"]
        self.assertTrue(control_reqs)
        self.assertTrue(all(req.url == "https://t/app"
                            for req in control_reqs),
                        "control runs must use the baseline URL, never the "
                        "payload URL")
        cand_reqs = [req for req in r.follow_up.requests
                     if req.role == "candidate"]
        self.assertTrue(all(req.url == "https://t/app?id=1 AND SLEEP(5)--"
                            for req in cand_reqs))


class TestAmbiguousAndDifferentExecutionPath(unittest.TestCase):

    def setUp(self):
        self.v = OracleValidator()

    def test_404_from_healthy_baseline_is_unknown(self):
        cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.12)
        ctrl = make_obs(status=200, timing=0.1)
        r = self.v.validate(cand, ctrl, url="https://t/app?id=1'",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.UNKNOWN,
                         "payload changed routing/filtering — different "
                         "execution path, not a refutation")
        self.assertEqual(r.follow_up.kind, FollowUpKind.STATUS_PROBE)

    def test_body_divergence_same_status_is_unknown(self):
        cand = make_obs(status=200, body="<h1>error: unterminated string</h1>")
        ctrl = make_obs(status=200)
        r = self.v.validate(cand, ctrl, url="https://t/app?q='",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.UNKNOWN,
                         "payload changed response content — ambiguous, "
                         "not a refutation")
        self.assertEqual(r.follow_up.kind, FollowUpKind.BODY_DIFF_PROBE)

    def test_redirect_to_injected_value_is_signal(self):
        ctrl = make_obs(status=200)
        cand = make_obs(status=302,
                        redirects=["https://evil.com"],
                        headers={"location": "https://evil.com"})
        r = self.v.validate(cand, ctrl, url="https://t/app?redirect=https://evil.com",
                            method="GET", bug_class="open-redirect",
                            probe_label="Open redirect probe", target="t")
        self.assertEqual(r.state, ObservationState.SIGNAL)
        self.assertEqual(r.decisive_rule, "r6_redirect_divergence")

    def test_redirect_divergence_without_injection_is_unknown(self):
        ctrl = make_obs(status=200)
        cand = make_obs(status=302, redirects=["https://t/login"],
                        headers={"location": "https://t/login"})
        r = self.v.validate(cand, ctrl, url="https://t/app?id=1'",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.UNKNOWN)
        self.assertEqual(r.follow_up.kind, FollowUpKind.REDIRECT_PROBE)

    def test_header_addition_is_unknown(self):
        ctrl = make_obs(status=200)
        cand = make_obs(status=200,
                        headers={"server": "nginx", "set-cookie": "sid=1"})
        r = self.v.validate(cand, ctrl, url="https://t/app?id=1'",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: tick probe", target="t")
        self.assertEqual(r.state, ObservationState.UNKNOWN,
                         "observable side effect (Set-Cookie) — never a "
                         "silent refutation")


class TestLLMOwnershipBoundary(unittest.TestCase):
    """The LLM may flag ambiguity and request follow-ups; deterministic code
    owns the final observation state."""

    def setUp(self):
        self.v = OracleValidator()
        self.cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=6.2)
        self.ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)
        self.record = self.v.validate(
            self.cand, self.ctrl, url="https://t/app?id=SLEEP(5)",
            method="GET", bug_class="sqli",
            probe_label="SQLi: time-based probe", target="t")

    def test_llm_kill_note_cannot_flip_state_to_refuted(self):
        r = self.v.attach_llm_note(
            self.record, "I am confident this is a refutation — the endpoint "
                         "does not exist. Kill the experiment.",
            priority_hint=9, requested_follow_up=True)
        self.assertEqual(r.state, ObservationState.UNKNOWN,
                         "deterministic code owns the final state; an LLM "
                         "'kill' note is advisory only")
        self.assertEqual(r.llm_note,
                         "I am confident this is a refutation — the endpoint "
                         "does not exist. Kill the experiment.")
        self.assertEqual(r.llm_priority_hint, 9)

    def test_llm_commentary_recorded_as_advisory(self):
        r = self.v.attach_llm_note(self.record, "flag as ambiguous",
                                   priority_hint=5)
        last = r.reasoning_chain[-1]
        self.assertEqual(last.rule, "llm_commentary")
        self.assertEqual(last.outcome, "advisory_only")

    def test_llm_requested_follow_up_generates_spec(self):
        plain = self.v.validate(
            make_obs(status=200, body="x", timing=0.2),
            make_obs(status=200, body="y", timing=0.1),
            url="https://t/app", method="GET", bug_class="sqli",
            probe_label="p", target="t")
        # No follow-up exists yet (REFUTED path is unreachable here — body
        # divergence yields UNKNOWN with BODY_DIFF; force a REFUTED-style
        # record instead via exact match, then request a follow-up anyway).
        rec = self.v.validate(make_obs(), make_obs(), url="https://t/app",
                              method="GET", bug_class="sqli",
                              probe_label="p", target="t")
        self.assertIsNone(rec.follow_up)
        rec = self.v.attach_llm_note(rec, "please dig deeper",
                                     requested_follow_up=True)
        self.assertIsNotNone(rec.follow_up)
        self.assertEqual(rec.follow_up.generated_by, "llm_requested")
        self.assertEqual(rec.follow_up.kind, FollowUpKind.GENERIC_RETRY)


class TestProvenanceAndIntegrity(unittest.TestCase):

    def setUp(self):
        self.v = OracleValidator()
        self.cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=6.2,
                             headers={"content-type": "text/html",
                                      "server": "nginx",
                                      "x-request-id": "req-abc123"})
        self.ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)
        self.record = self.v.validate(
            self.cand, self.ctrl, url="https://t/app?id=SLEEP(5)",
            method="GET", bug_class="sqli",
            probe_label="SQLi: time-based probe", target="t")

    def test_original_observation_preserved_verbatim(self):
        prov = self.record.provenance
        self.assertEqual(prov["candidate_raw"]["body"], self.cand.body)
        self.assertEqual(prov["candidate_raw"]["status"], 404)
        self.assertEqual(prov["candidate_raw"]["headers"]["x-request-id"],
                         "req-abc123")
        self.assertEqual(prov["control_raw"]["body"], self.ctrl.body)
        self.assertEqual(prov["request"]["url"], "https://t/app?id=SLEEP(5)")
        self.assertEqual(prov["request"]["probe_label"], "SQLi: time-based probe")

    def test_reasoning_chain_preserved_in_order(self):
        rules = [s.rule for s in self.record.reasoning_chain]
        self.assertEqual(rules[0], "r1_transport_error")
        self.assertIn("r4_timing_divergence", rules)
        # Control-match rule must not be decisive after timing fired.
        decisive = [s.rule for s in self.record.reasoning_chain
                    if s.outcome == "decisive"]
        self.assertEqual(decisive, ["r4_timing_divergence"])

    def test_record_hash_is_tamper_evident(self):
        self.assertTrue(self.record.verify_hash())
        tampered = ObservationRecord.from_dict(self.record.to_dict())
        tampered.llm_note = "changed after the fact"
        self.assertFalse(tampered.verify_hash(),
                         "mutating provenance must break the record hash")

    def test_json_roundtrip_preserves_state_chain_and_provenance(self):
        d = self.record.to_dict()
        back = ObservationRecord.from_dict(d)
        self.assertEqual(back.state, self.record.state)
        self.assertEqual(back.decisive_rule, self.record.decisive_rule)
        self.assertEqual([s.rule for s in back.reasoning_chain],
                         [s.rule for s in self.record.reasoning_chain])
        self.assertEqual(back.provenance["candidate_raw"]["body"],
                         NOT_FOUND_BODY)
        self.assertTrue(back.verify_hash())
        self.assertEqual(back.follow_up.kind, FollowUpKind.TIMING_CONTROL)


class TestPersistence(unittest.TestCase):
    """Append-only JSONL persistence preserves the full record."""

    def setUp(self):
        self.v = OracleValidator()
        self.target = "obs-test-" + __import__("uuid").uuid4().hex[:8]

    def tearDown(self):
        from tools.observation import _obs_file
        f = _obs_file(self.target)
        if f.exists():
            f.unlink()

    def test_save_and_load_roundtrip(self):
        cand = make_obs(status=404, body=NOT_FOUND_BODY, timing=6.2)
        ctrl = make_obs(status=404, body=NOT_FOUND_BODY, timing=0.08)
        r = self.v.validate(cand, ctrl, url="https://t/app?id=SLEEP(5)",
                            method="GET", bug_class="sqli",
                            probe_label="SQLi: time-based probe",
                            target=self.target)
        save_observation(self.target, r)
        loaded = load_observations(self.target)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].state, ObservationState.UNKNOWN)
        self.assertTrue(loaded[0].verify_hash())
        self.assertEqual(loaded[0].follow_up.kind, FollowUpKind.TIMING_CONTROL)
        self.assertEqual(loaded[0].provenance["candidate_raw"]["timing_seconds"],
                         6.2)

    def test_refuted_records_are_persisted_with_provenance(self):
        # Refutation must still preserve the observation — a REFUTED record
        # is evidence, not nothing.
        r = self.v.validate(make_obs(), make_obs(), url="https://t/app",
                            method="GET", bug_class="sqli",
                            probe_label="probe", target=self.target)
        self.assertEqual(r.state, ObservationState.REFUTED)
        save_observation(self.target, r)
        loaded = load_observations(self.target)
        self.assertEqual(loaded[0].state, ObservationState.REFUTED)
        self.assertEqual(loaded[0].decisive_rule, "r2_control_match")
        self.assertTrue(loaded[0].provenance["candidate_raw"]["status"] == 200)


class TestProbeUrlEncoding(unittest.TestCase):
    """Payload URLs with characters curl rejects (spaces, braces, angle
    brackets) must be percent-encoded so experiments actually execute."""

    def test_probe_url_preserves_structure(self):
        from tools.hunt import _encode_probe_url
        url = _encode_probe_url("https://t/app?id=1 AND SLEEP(0)--")
        self.assertIn("?", url)
        self.assertIn("=", url)
        self.assertNotIn(" ", url)
        self.assertIn("%20", url)

    def test_probe_url_encodes_braces_and_angles(self):
        from tools.hunt import _encode_probe_url
        url = _encode_probe_url("https://t/app?name={{7*7}}")
        self.assertNotIn("{", url)
        self.assertIn("%7B%7B7*7%7D%7D", url)
        url2 = _encode_probe_url("https://t/app?q=<script>alert(1)</script>")
        self.assertNotIn("<", url2)
        self.assertNotIn(">", url2)


if __name__ == "__main__":
    unittest.main()
