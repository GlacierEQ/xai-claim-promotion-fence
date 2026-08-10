import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
TARGET = json.loads((ROOT / "machine" / "target-contract.json").read_text(encoding="utf-8"))

EXPECTED_PROMOTED_TRANSITIONS = [
    ("DISCOVERED", "IDENTITY_RESOLVED", "IDENTITY_RESOLVED"),
    ("IDENTITY_RESOLVED", "PROBLEM_VERIFIED", "PROBLEM_VERIFIED"),
    ("PROBLEM_VERIFIED", "TARGET_CONTRACTED", "TARGET_CONTRACT_FROZEN"),
    ("TARGET_CONTRACTED", "SEEDED", "DONOR_PLAN_RESOLVED"),
    ("SEEDED", "VERTICAL_SLICE", "VERTICAL_SLICE_ALIVE"),
    ("VERTICAL_SLICE", "IMPLEMENTED", "CENTRAL_MECHANISM_PRESENT"),
    ("IMPLEMENTED", "TESTED", "DETERMINISTIC_PROOF_GREEN"),
    ("TESTED", "ADVERSARIAL_VERIFIED", "ADVERSARIAL_SURVIVAL"),
    ("ADVERSARIAL_VERIFIED", "OPERABLE", "OPERABLE_AND_OBSERVABLE"),
    ("OPERABLE", "PROOF_REPRODUCED", "PROOF_RECEIPT_BOUND"),
    ("PROOF_REPRODUCED", "PROMOTED", "AUTHORITY_BOUND"),
]


class ExcellenceStateContractTests(unittest.TestCase):
    def test_state_stays_promoted_until_exact_canonical_proof(self):
        self.assertEqual(STATE["principal_state"], "PROMOTED")
        self.assertEqual(STATE["state"], "PROMOTED")
        self.assertEqual(
            STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"],
            "PENDING",
        )
        self.assertEqual(POSITION["position_state"], "CANDIDATE")
        self.assertEqual(POSITION["role"], "CANONICAL_SPECIALIST_CANDIDATE")
        self.assertTrue(TARGET["current"]["canonical_position_pending_exact_head_proof"])

    def test_history_is_ordered_and_stops_at_promoted(self):
        actual = [(step["from"], step["to"], step["gate"]) for step in STATE["history"]]
        self.assertEqual(actual, EXPECTED_PROMOTED_TRANSITIONS)
        self.assertTrue(all(step["result"] == "PASS" for step in STATE["history"]))
        self.assertEqual(STATE["history"][-1]["to"], STATE["principal_state"])

    def test_candidate_position_preserves_identity_and_lineage(self):
        self.assertEqual(POSITION["repository"], STATE["repository"])
        policy = POSITION["integration_policy"]
        for field in (
            "preserve_repository_identity",
            "preserve_lineage",
            "presentation_independent",
            "absorption_requires_functional_equivalence",
            "absorption_requires_proof_equivalence",
        ):
            self.assertIs(policy[field], True)
        self.assertFalse(TARGET["donor_plan"]["integration_exercised"])

    def test_candidate_next_evolution_is_material_but_not_claimed_complete(self):
        declared = POSITION["next_evolution_if_proven"].lower()
        self.assertIn("actuation lifecycle bus", declared)
        self.assertIn("rollback", declared)
        self.assertIn("operational authority", declared)
        self.assertEqual(
            STATE["evolution_cursor"],
            "next:canonical_position_only_if_estate_role_resolved",
        )


if __name__ == "__main__":
    unittest.main()
