from __future__ import annotations
import unittest
from src.claim_fence import allow_claim, Stage, max_stage

class Adv(unittest.TestCase):
    def test_empty_evidence_blocks_production(self):
        ok, reason = allow_claim([], Stage.PRODUCTION_CLAIM)
        self.assertFalse(ok)
    def test_partial_evidence_not_integrated(self):
        self.assertEqual(max_stage(["unit_tests"]), Stage.TESTED)
    def test_missing_ops_signoff_blocks_production(self):
        ok, _ = allow_claim(["unit_tests", "cross_pillar_receipt", "uptime"], Stage.PRODUCTION_CLAIM)
        self.assertFalse(ok)

