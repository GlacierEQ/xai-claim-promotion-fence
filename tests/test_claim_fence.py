from __future__ import annotations
import unittest
from src.claim_fence import Stage, allow_claim, max_stage

class CFTests(unittest.TestCase):
    def test_sim_only(self):
        self.assertEqual(max_stage([]), Stage.SIM)
        ok, _ = allow_claim([], Stage.PRODUCTION_CLAIM)
        self.assertFalse(ok)

    def test_integrated(self):
        ev = {"unit_tests", "cross_pillar_receipt"}
        self.assertEqual(max_stage(ev), Stage.INTEGRATED)

if __name__ == "__main__":
    unittest.main()
