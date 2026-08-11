import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
TARGET = json.loads((ROOT / "machine" / "target-contract.json").read_text(encoding="utf-8"))
PROOF = json.loads((ROOT / "machine" / "canonical-proof-receipt.json").read_text(encoding="utf-8"))

EXPECTED_TRANSITIONS = [
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
    ("PROMOTED", "CANONICAL", "CANONICAL_POSITION_RESOLVED"),
    ("CANONICAL", "EVOLVING", "EVOLUTION_CURSOR_DEFINED"),
]


class ExcellenceStateContractTests(unittest.TestCase):
    def test_state_is_canonical_and_evolving_without_claim_inflation(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["state"], "EVOLVING")
        self.assertEqual(STATE["claim_ceiling"], "PROMOTED")
        self.assertEqual(STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"], "PASS")
        self.assertEqual(STATE["gates"]["EVOLUTION_CURSOR_DEFINED"]["status"], "PASS")
        self.assertEqual(POSITION["position_state"], "RESOLVED")
        self.assertEqual(POSITION["role"], "company_specific_specialist_system")
        self.assertTrue(TARGET["current"]["canonical_position_resolved"])
        self.assertFalse(TARGET["current"]["canonical_position_pending_exact_head_proof"])
        self.assertEqual(TARGET["external_claim_ceiling"], "PROMOTED")

    def test_history_is_ordered_and_non_skipping(self):
        actual = [(step["from"], step["to"], step["gate"]) for step in STATE["history"]]
        self.assertEqual(actual, EXPECTED_TRANSITIONS)
        self.assertTrue(all(step["result"] == "PASS" for step in STATE["history"]))
        self.assertEqual(STATE["history"][-1]["to"], STATE["principal_state"])

    def test_exact_cross_language_proof_is_bound(self):
        self.assertEqual(PROOF["tested_candidate"]["sha"], "7d86082e299cbed21914b5f62d296d42fbed6384")
        self.assertEqual(PROOF["tested_candidate"]["workflow_run"], 31450384429)
        self.assertEqual(PROOF["lanes"]["python"]["result"], "PASS")
        self.assertEqual(PROOF["lanes"]["node"]["result"], "PASS")
        self.assertEqual(PROOF["external_claim_ceiling"], "PROMOTED")

    def test_position_preserves_identity_lineage_and_sibling_boundary(self):
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
        self.assertFalse(PROOF["truth_boundary"]["actuation_bus_integration_exercised"])

    def test_evolution_cursor_is_material_and_does_not_imply_completion(self):
        declared = POSITION["next_evolution"].lower()
        self.assertIn("actuation lifecycle bus", declared)
        self.assertIn("rollback", declared)
        self.assertIn("operational authority", declared)
        self.assertEqual(
            STATE["evolution_cursor"],
            "next:receipt_level_composition_with_actuation_bus_and_rollback_propagation",
        )


if __name__ == "__main__":
    unittest.main()
