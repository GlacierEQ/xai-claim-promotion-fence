import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))

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


def normalize(text):
    return " ".join(text.lower().replace("/", " ").replace("+", " ").replace("-", " ").split())


class ExcellenceStateContractTests(unittest.TestCase):
    def test_state_is_canonical_and_evolving(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"], "PASS")
        self.assertEqual(STATE["gates"]["EVOLUTION_CURSOR_DEFINED"]["status"], "PASS")
        self.assertEqual(STATE["canonical_position_ref"], "machine/canonical-position.json")

    def test_history_is_ordered_and_non_skipping(self):
        actual = [(step["from"], step["to"], step["gate"]) for step in STATE["history"]]
        self.assertEqual(actual, EXPECTED_TRANSITIONS)
        self.assertTrue(all(step["result"] == "PASS" for step in STATE["history"]))
        self.assertEqual(STATE["history"][-1]["to"], STATE["principal_state"])

    def test_position_preserves_identity_and_lineage(self):
        self.assertEqual(POSITION["repository"], STATE["repository"])
        p = POSITION["integration_policy"]
        self.assertEqual(POSITION["position_state"], "RESOLVED")
        for field in (
            "preserve_repository_identity",
            "preserve_lineage",
            "presentation_independent",
            "absorption_requires_functional_equivalence",
            "absorption_requires_proof_equivalence",
        ):
            self.assertIs(p[field], True)

    def test_evolution_cursor_is_material_and_bound(self):
        prefix = "next:"
        self.assertTrue(STATE["evolution_cursor"].startswith(prefix))
        self.assertNotIn("canonical_position_only_if_estate_role_resolved", STATE["evolution_cursor"])
        self.assertIsInstance(POSITION["next_evolution"], str)
        self.assertTrue(POSITION["next_evolution"].strip())
        cursor = normalize(STATE["evolution_cursor"][len(prefix):])
        declared = normalize(POSITION["next_evolution"])
        for concept in ("multi source evidence quorum", "rollback", "dependency aware", "authority"):
            self.assertIn(concept, cursor)
            self.assertIn(concept, declared)


if __name__ == "__main__":
    unittest.main()
