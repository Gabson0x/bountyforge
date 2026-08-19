#!/usr/bin/env python3
"""
Regression tests for the BountyForge Lead Ledger (tools/leads.py).

Run:  python3 -m unittest discover -s tests -v

Guards the core invariants of the OPEN LEAD doctrine:
  1. An OPEN LEAD is a persistent state-transition research object — it
     survives re-load, records every transition, and is never a dropped
     journal line.
  2. Missing preconditions are tracked by name and resolve only with evidence.
  3. The mutation loop mutates ONE variable per attempt and never suggests
     repeating an exact (variable, value) pair.
  4. Kill guard: kill_lead() REFUSES without BOTH half-refutations, auto-parks
     the lead into the chain pool, and counts the dismissal attempt.
  5. PARKED leads stay in the chain pool and surface as A->B chain partners.

Headline regression: the premature-kill case. An agent proves a trigger but
cannot trace impact and wants to kill the lead. The ledger must refuse, park
the lead, and later surface it as a chain partner for a new finding — the
"lead that wasn't a bug" becomes the breakthrough half.
"""

import sys
import shutil
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
TEST_TARGETS = ["t1.example.com", "t2.example.com", "t3.example.com",
                "t4.example.com", "t5.example.com", "t6.example.com",
                "t7.example.com", "t8.example.com"]


class LeadTestCase(unittest.TestCase):
    """Isolates test state — session dirs persist across runs."""

    def setUp(self):
        for t in TEST_TARGETS:
            shutil.rmtree(ROOT / "state" / "sessions" / t, ignore_errors=True)


from tools.leads import (
    Lead, Precondition, MutationAttempt,
    create_lead, load_leads, get_lead,
    set_half, add_precondition, resolve_precondition,
    mutate_lead, next_mutation,
    promote_to_finding, park_lead, kill_lead, find_chain_partners,
)
from tools.state import get_findings, load_state


class TestLeadPersistence(LeadTestCase):

    def test_create_and_reload_lead(self):
        lead = create_lead("t1.example.com", "SSRF in /fetch",
                           q_trigger="can we reach the fetch param?",
                           q_impact="what internal data is reachable?",
                           payload="curl -s 'https://t/fetch?url=http://169.254.169.254'",
                           preconditions=["metadata endpoint:need to confirm 169.254.169.254 responds"])
        reloaded = get_lead("t1.example.com", lead.lead_id)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.title, "SSRF in /fetch")
        self.assertEqual(reloaded.state, "OPEN")
        self.assertEqual(reloaded.preconditions[0]["status"], "missing")
        self.assertEqual(reloaded.trigger_half, "untraced")

    def test_lead_id_is_stable(self):
        lead = create_lead("t1.example.com", "stable id lead")
        again = get_lead("t1.example.com", lead.lead_id)
        self.assertEqual(again.lead_id, lead.lead_id)

    def test_state_counter_synced(self):
        create_lead("t2.example.com", "counter lead")
        state = load_state("t2.example.com")
        self.assertEqual(state.leads_open, 1)


class TestStateMachine(LeadTestCase):

    def test_both_halves_proven_recomputes_to_finding(self):
        lead = create_lead("t3.example.com", "IDOR read")
        set_half("t3.example.com", lead.lead_id, "trigger", "proven",
                 evidence="GET /api/users/1 with attacker token returns victim data")
        lead = get_lead("t3.example.com", lead.lead_id)
        self.assertEqual(lead.state, "OPEN")  # impact still untraced
        set_half("t3.example.com", lead.lead_id, "impact", "proven",
                 evidence="passport number of any user leaked")
        lead = get_lead("t3.example.com", lead.lead_id)
        self.assertEqual(lead.state, "FINDING")

    def test_proven_verdict_requires_evidence(self):
        lead = create_lead("t3.example.com", "evidence required")
        res = set_half("t3.example.com", lead.lead_id, "trigger", "proven", evidence="")
        self.assertFalse(res["ok"])
        self.assertIn("requires evidence", res["error"])

    def test_untraced_verdict_keeps_lead_open_without_evidence(self):
        lead = create_lead("t3.example.com", "half unresolved")
        res = set_half("t3.example.com", lead.lead_id, "impact", "untraced", evidence="")
        self.assertTrue(res["ok"])

    def test_both_refuted_kills(self):
        lead = create_lead("t3.example.com", "killable")
        res = kill_lead("t3.example.com", lead.lead_id,
                        trigger_refutation="endpoint removed from router",
                        impact_refutation="endpoint serves only static cache, no user data")
        self.assertTrue(res["ok"])
        self.assertTrue(res["killed"])
        lead = get_lead("t3.example.com", lead.lead_id)
        self.assertEqual(lead.state, "KILLED")
        self.assertEqual(lead.trigger_half, "refuted")
        self.assertEqual(lead.impact_half, "refuted")


class TestKillGuard(LeadTestCase):
    """The anti-dismissal lock: a one-half refutation is NEVER a kill."""

    def test_kill_without_any_refutation_refused_and_parked(self):
        lead = create_lead("t4.example.com", "premature kill target",
                           preconditions=["second account:need cross-account proof"])
        res = kill_lead("t4.example.com", lead.lead_id)
        self.assertFalse(res["ok"])
        self.assertTrue(res["parked"])
        lead = get_lead("t4.example.com", lead.lead_id)
        self.assertEqual(lead.state, "PARKED")
        self.assertEqual(lead.dismissal_attempts, 1)
        self.assertEqual(len(lead.kill_refusal_reasons), 1)
        self.assertIn("MISSING", lead.kill_refusal_reasons[0])

    def test_kill_with_only_trigger_refutation_refused(self):
        lead = create_lead("t4.example.com", "half refuted kill attempt")
        res = kill_lead("t4.example.com", lead.lead_id,
                        trigger_refutation="path unreachable",
                        impact_refutation="")
        self.assertFalse(res["killed"])
        lead = get_lead("t4.example.com", lead.lead_id)
        self.assertEqual(lead.state, "PARKED")
        self.assertEqual(lead.dismissal_attempts, 1)
        self.assertNotEqual(lead.impact_half, "refuted")

    def test_kill_with_only_impact_refutation_refused(self):
        lead = create_lead("t4.example.com", "impact only kill attempt")
        res = kill_lead("t4.example.com", lead.lead_id,
                        trigger_refutation="",
                        impact_refutation="harm proven nonexistent")
        self.assertFalse(res["killed"])
        self.assertTrue(res["parked"])

    def test_repeated_dismissal_attempts_counted(self):
        lead = create_lead("t4.example.com", "repeated dismissal")
        for _ in range(3):
            kill_lead("t4.example.com", lead.lead_id,
                      trigger_refutation="path unreachable")
        lead = get_lead("t4.example.com", lead.lead_id)
        self.assertEqual(lead.dismissal_attempts, 3)
        self.assertEqual(lead.state, "PARKED")


class TestPreconditions(LeadTestCase):

    def test_add_and_resolve_precondition_with_evidence(self):
        lead = create_lead("t5.example.com", "precondition lead")
        add_precondition("t5.example.com", lead.lead_id,
                         "race window", "need a 2-account concurrent test")
        lead = get_lead("t5.example.com", lead.lead_id)
        self.assertEqual(len(lead.preconditions), 1)

        res = resolve_precondition("t5.example.com", lead.lead_id,
                                   "race window", "present",
                                   evidence="two accounts raced, 2x redeem accepted")
        self.assertTrue(res["ok"])
        lead = get_lead("t5.example.com", lead.lead_id)
        self.assertEqual(lead.preconditions[0]["status"], "present")
        self.assertIn("raced", lead.preconditions[0]["proven_by"])

    def test_resolve_without_evidence_refused(self):
        lead = create_lead("t5.example.com", "evidence gate")
        add_precondition("t5.example.com", lead.lead_id, "admin role", "")
        res = resolve_precondition("t5.example.com", lead.lead_id,
                                   "admin role", "refuted", evidence="")
        self.assertFalse(res["ok"])

    def test_duplicate_precondition_rejected(self):
        lead = create_lead("t5.example.com", "dup precondition")
        add_precondition("t5.example.com", lead.lead_id, "second account", "")
        res = add_precondition("t5.example.com", lead.lead_id, "second account", "")
        self.assertFalse(res["ok"])


class TestMutationLoop(LeadTestCase):
    """One variable per attempt; no repeated (variable, value) pairs."""

    def test_mutation_moves_lead_to_mutating(self):
        lead = create_lead("t6.example.com", "mutation lead")
        res = mutate_lead("t6.example.com", lead.lead_id,
                          "payload encoding", "%27", "%2527",
                          result="advanced", evidence="WAF bypassed")
        self.assertTrue(res["ok"])
        lead = get_lead("t6.example.com", lead.lead_id)
        self.assertEqual(lead.state, "MUTATING")
        self.assertEqual(len(lead.mutation_attempts), 1)
        self.assertEqual(lead.mutation_attempts[0]["variable"], "payload encoding")

    def test_same_value_mutation_refused(self):
        lead = create_lead("t6.example.com", "no-op mutation")
        res = mutate_lead("t6.example.com", lead.lead_id,
                          "payload encoding", "%27", "%27")
        self.assertFalse(res["ok"])
        self.assertIn("no variable was mutated", res["error"])

    def test_advanced_result_requires_evidence(self):
        lead = create_lead("t6.example.com", "evidence gate mutation")
        res = mutate_lead("t6.example.com", lead.lead_id,
                          "account", "user_a", "user_b",
                          result="advanced", evidence="")
        self.assertFalse(res["ok"])

    def test_next_mutation_picks_first_missing_precondition(self):
        lead = create_lead("t6.example.com", "suggestion lead",
                           preconditions=["second account:need cross-account proof",
                                          "admin role:need admin token"])
        nxt = next_mutation("t6.example.com", lead.lead_id)
        self.assertEqual(nxt["variable"], "second account")
        self.assertEqual(nxt["remaining_missing"], 2)

    def test_next_mutation_never_repeats_tried_pair(self):
        lead = create_lead("t6.example.com", "anti-repeat lead",
                           preconditions=["payload encoding:WAF blocks single quote"])
        mutate_lead("t6.example.com", lead.lead_id,
                    "payload encoding", "%27", "%2527",
                    result="unchanged", evidence="WAF still blocks")
        nxt = next_mutation("t6.example.com", lead.lead_id)
        self.assertEqual(nxt["variable"], "payload encoding")
        self.assertIn("NEW VALUE", nxt["suggestion"].upper())
        self.assertNotEqual(nxt["new_value"], "%2527")

    def test_parked_lead_reactivates_on_mutation(self):
        lead = create_lead("t6.example.com", "parked revival")
        park_lead("t6.example.com", lead.lead_id)
        lead = get_lead("t6.example.com", lead.lead_id)
        self.assertEqual(lead.state, "PARKED")
        mutate_lead("t6.example.com", lead.lead_id,
                    "endpoint sibling", "/v1", "/v2",
                    result="unchanged", evidence="same behavior")
        lead = get_lead("t6.example.com", lead.lead_id)
        self.assertEqual(lead.state, "MUTATING")


class TestParkAndChainPool(LeadTestCase):

    def test_park_keeps_lead_alive(self):
        lead = create_lead("t7.example.com", "park me")
        res = park_lead("t7.example.com", lead.lead_id, reason="need new OAuth endpoint")
        self.assertTrue(res["ok"])
        lead = get_lead("t7.example.com", lead.lead_id)
        self.assertEqual(lead.state, "PARKED")
        self.assertIsNotNone(lead)  # not deleted, not killed

    def test_park_killed_lead_refused(self):
        lead = create_lead("t7.example.com", "already killed")
        kill_lead("t7.example.com", lead.lead_id,
                  trigger_refutation="dead path",
                  impact_refutation="no harm")
        res = park_lead("t7.example.com", lead.lead_id)
        self.assertFalse(res["ok"])

    def test_chain_partner_discovery_from_parked_lead(self):
        """Headline regression: the 'not a bug' lead becomes the breakthrough half."""
        lead = create_lead("t7.example.com", "open redirect in /goto",
                           payload="https://t/goto?next=https://evil.com",
                           preconditions=["oauth endpoint:need a partner to complete ATO"])
        set_half("t7.example.com", lead.lead_id, "trigger", "proven",
                 evidence="302 to attacker-controlled URL")
        set_half("t7.example.com", lead.lead_id, "impact", "untraced", evidence="")
        park_lead("t7.example.com", lead.lead_id, reason="open redirect alone is below bar")

        promote_to_finding("t7.example.com", "nonexistent-id")  # no-op, stays parked
        from tools.state import add_finding
        add_finding("t7.example.com", {
            "title": "OAuth misconfig in /oauth/authorize — state not validated",
            "bug_class": "oauth_misconfig", "endpoint": "/oauth/authorize",
            "severity": "medium",
        })

        partners = find_chain_partners("t7.example.com", lead.lead_id)
        self.assertTrue(partners["ok"])
        self.assertEqual(len(partners["partners"]), 1)
        self.assertIn("oauth", partners["partners"][0]["partner_title"].lower())


class TestPromotion(LeadTestCase):

    def test_promote_requires_both_halves_proven(self):
        lead = create_lead("t8.example.com", "not ready")
        set_half("t8.example.com", lead.lead_id, "trigger", "proven",
                 evidence="fires")
        res = promote_to_finding("t8.example.com", lead.lead_id)
        self.assertFalse(res["ok"])
        self.assertIn("both must be 'proven'", res["error"])

    def test_promote_creates_finding_with_payload_and_chain_parent(self):
        lead = create_lead("t8.example.com", "ready to promote",
                           payload="curl -s exploit",
                           chain_partners=["partner-finding-1"])
        set_half("t8.example.com", lead.lead_id, "trigger", "proven",
                 evidence="reachable entry point")
        set_half("t8.example.com", lead.lead_id, "impact", "proven",
                 evidence="victim funds stuck forever")
        res = promote_to_finding("t8.example.com", lead.lead_id)
        self.assertTrue(res["ok"])

        findings = get_findings("t8.example.com")
        promoted = [f for f in findings if f["finding_id"] == res["finding_id"]]
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["proof_of_concept"], "curl -s exploit")
        self.assertEqual(promoted[0]["chain_parent"], "partner-finding-1")

        lead = get_lead("t8.example.com", lead.lead_id)
        self.assertEqual(lead.state, "FINDING")


if __name__ == "__main__":
    unittest.main()