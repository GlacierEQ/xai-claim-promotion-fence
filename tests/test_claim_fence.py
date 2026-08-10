from __future__ import annotations

import math
import unittest

from src.claim_fence import (
    Claim,
    ClaimPromotionFenceEngine,
    EvidenceReceipt,
    POLICY_FINGERPRINT,
    Stage,
    allow_claim,
    max_stage,
)


def d(char: str) -> str:
    return char * 64


def receipt(
    kind: str,
    *,
    digest_char: str,
    signer: str = "signer-1",
    timestamp: float = 100.0,
    claim_id: str = "claim-1",
    repository: str = "GlacierEQ/repo",
    source_sha: str = "sha-1",
    revoked: bool = False,
) -> EvidenceReceipt:
    return EvidenceReceipt(
        kind,
        d(digest_char),
        signer,
        timestamp,
        claim_id,
        repository,
        source_sha,
        revoked,
    )


def claim(
    stage: Stage,
    receipts: frozenset[EvidenceReceipt],
    *,
    claim_id: str = "claim-1",
    repository: str = "GlacierEQ/repo",
    source_sha: str = "sha-1",
    prereqs: frozenset[str] = frozenset(),
) -> Claim:
    return Claim(claim_id, repository, source_sha, stage, receipts, prereqs)


class ClaimFenceTests(unittest.TestCase):
    def test_legacy_helpers_are_label_only_and_fail_closed_by_stage(self):
        self.assertEqual(max_stage([]), Stage.SIM)
        ok, _ = allow_claim([], Stage.PRODUCTION_CLAIM)
        self.assertFalse(ok)
        self.assertEqual(
            max_stage({"unit_tests", "cross_pillar_receipt"}),
            Stage.INTEGRATED,
        )

    def test_scoped_receipts_reach_integrated(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        evidence = frozenset(
            {
                receipt("unit_tests", digest_char="a"),
                receipt("cross_pillar_receipt", digest_char="b"),
            }
        )
        c = claim(Stage.INTEGRATED, evidence)
        decision = engine.evaluate_claim_promotion(c, now=110.0)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.max_achievable_stage, Stage.INTEGRATED)
        self.assertEqual(decision.policy_fingerprint, POLICY_FINGERPRINT)
        self.assertEqual(len(decision.evidence_fingerprints), 2)

    def test_unrelated_claim_receipts_do_not_promote(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        evidence = frozenset(
            {
                receipt(
                    "unit_tests",
                    digest_char="a",
                    claim_id="other-claim",
                ),
                receipt(
                    "cross_pillar_receipt",
                    digest_char="b",
                    repository="GlacierEQ/other",
                ),
            }
        )
        c = claim(Stage.TESTED, evidence)
        decision = engine.evaluate_claim_promotion(c, now=110.0)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.max_achievable_stage, Stage.SIM)
        self.assertEqual(decision.evidence_fingerprints, ())

    def test_future_and_receipt_revocation_fail_closed(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        future = receipt("unit_tests", digest_char="a", timestamp=120.0)
        c = claim(Stage.TESTED, frozenset({future}))
        self.assertEqual(
            engine.evaluate_claim_promotion(c, now=110.0).max_achievable_stage,
            Stage.SIM,
        )

        current = receipt("unit_tests", digest_char="b", timestamp=100.0)
        current_claim = claim(Stage.TESTED, frozenset({current}))
        self.assertTrue(engine.evaluate_claim_promotion(current_claim, now=110.0).allowed)
        engine.revoke_receipt(current.digest)
        revoked = engine.evaluate_claim_promotion(current_claim, now=110.0)
        self.assertFalse(revoked.allowed)
        self.assertEqual(revoked.max_achievable_stage, Stage.SIM)

    def test_quorum_counts_unique_signers_per_kind(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        one_signer = frozenset(
            {
                receipt("unit_tests", digest_char="a", signer="s1"),
                receipt("unit_tests", digest_char="b", signer="s1"),
            }
        )
        c = claim(Stage.TESTED, one_signer)
        self.assertFalse(
            engine.evaluate_claim_promotion(c, required_quorum=2, now=110.0).allowed
        )

        two_signers = frozenset(
            {
                receipt("unit_tests", digest_char="a", signer="s1"),
                receipt("unit_tests", digest_char="b", signer="s2"),
            }
        )
        c2 = claim(Stage.TESTED, two_signers)
        self.assertTrue(
            engine.evaluate_claim_promotion(c2, required_quorum=2, now=110.0).allowed
        )

    def test_grant_binds_claim_policy_evidence_and_expiry(self):
        engine = ClaimPromotionFenceEngine(b"secret", default_ttl_s=10.0)
        evidence = frozenset({receipt("unit_tests", digest_char="a")})
        c = claim(Stage.TESTED, evidence)
        grant = engine.issue_promotion_grant(c, now=100.0)
        self.assertEqual(grant.claim_fingerprint, c.identity_fingerprint())
        self.assertEqual(grant.policy_fingerprint, POLICY_FINGERPRINT)
        self.assertEqual(grant.evidence_digests, (d("a"),))
        self.assertEqual(engine.verify_promotion_grant(grant, now=109.0), (True, None))
        self.assertEqual(
            engine.verify_promotion_grant(grant, now=111.0),
            (False, "GRANT_EXPIRED"),
        )

    def test_receipt_revocation_invalidates_existing_grant(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        evidence = frozenset({receipt("unit_tests", digest_char="a")})
        c = claim(Stage.TESTED, evidence)
        grant = engine.issue_promotion_grant(c, now=100.0)
        engine.revoke_receipt(d("a"))
        self.assertEqual(
            engine.verify_promotion_grant(grant, now=101.0),
            (False, "EVIDENCE_REVOKED"),
        )

    def test_prerequisite_must_remain_active_and_stage_sufficient(self):
        engine = ClaimPromotionFenceEngine(b"secret", default_ttl_s=100.0)
        prereq_evidence = frozenset(
            {
                receipt("unit_tests", digest_char="a", claim_id="base"),
                receipt("cross_pillar_receipt", digest_char="b", claim_id="base"),
            }
        )
        base = claim(
            Stage.INTEGRATED,
            prereq_evidence,
            claim_id="base",
        )
        base_grant = engine.issue_promotion_grant(base, now=100.0)
        self.assertEqual(engine.verify_promotion_grant(base_grant, now=101.0), (True, None))

        child_evidence = frozenset(
            {
                receipt("unit_tests", digest_char="c", claim_id="child"),
                receipt("cross_pillar_receipt", digest_char="d", claim_id="child"),
            }
        )
        child = claim(
            Stage.INTEGRATED,
            child_evidence,
            claim_id="child",
            prereqs=frozenset({"base"}),
        )
        self.assertTrue(engine.evaluate_claim_promotion(child, now=101.0).allowed)
        engine.revoke_receipt(d("a"))
        decision = engine.evaluate_claim_promotion(child, now=102.0)
        self.assertFalse(decision.allowed)
        self.assertIn("PREREQUISITE_INVALID_base_EVIDENCE_REVOKED", decision.reason or "")

    def test_claim_id_cannot_rebind_repository_or_source(self):
        engine = ClaimPromotionFenceEngine(b"secret")
        first_receipt = receipt("unit_tests", digest_char="a")
        first = claim(Stage.TESTED, frozenset({first_receipt}))
        engine.issue_promotion_grant(first, now=100.0)

        second_receipt = receipt(
            "unit_tests",
            digest_char="b",
            repository="GlacierEQ/other",
            source_sha="sha-2",
        )
        second = claim(
            Stage.TESTED,
            frozenset({second_receipt}),
            repository="GlacierEQ/other",
            source_sha="sha-2",
        )
        with self.assertRaisesRegex(ValueError, "different claim identity"):
            engine.issue_promotion_grant(second, now=101.0)

    def test_invalid_quorum_time_and_ttl_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            ClaimPromotionFenceEngine(b"secret", default_ttl_s=0)
        with self.assertRaisesRegex(ValueError, "finite"):
            ClaimPromotionFenceEngine(b"secret", default_ttl_s=math.nan)
        engine = ClaimPromotionFenceEngine(b"secret")
        c = claim(Stage.SIM, frozenset())
        with self.assertRaisesRegex(ValueError, "positive integer"):
            engine.evaluate_claim_promotion(c, required_quorum=0, now=100.0)
        with self.assertRaisesRegex(ValueError, "finite"):
            engine.evaluate_claim_promotion(c, now=math.nan)

    def test_evidence_receipt_requires_scoped_machine_identity(self):
        with self.assertRaisesRegex(ValueError, "sha256"):
            EvidenceReceipt(
                "unit_tests", "not-a-digest", "s1", 100.0,
                "claim-1", "GlacierEQ/repo", "sha-1"
            )
        with self.assertRaisesRegex(ValueError, "finite"):
            EvidenceReceipt(
                "unit_tests", d("a"), "s1", math.inf,
                "claim-1", "GlacierEQ/repo", "sha-1"
            )


if __name__ == "__main__":
    unittest.main()
