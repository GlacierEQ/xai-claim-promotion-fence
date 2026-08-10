"""Production-Ready Claim Promotion Fence Engine (Python).

Enforces Law 1: Real algorithms, zero fake wrappers, fail-closed validation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import time
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple


class Stage(str, Enum):
    SIM = "SIM"
    TESTED = "TESTED"
    INTEGRATED = "INTEGRATED"
    PRODUCTION_CLAIM = "PRODUCTION_CLAIM"


# Monotonic rank progression
_RANK: Dict[Stage, int] = {
    Stage.SIM: 0,
    Stage.TESTED: 1,
    Stage.INTEGRATED: 2,
    Stage.PRODUCTION_CLAIM: 3,
}

# Required evidence kinds per stage
_REQUIRED_EVIDENCE: Dict[Stage, FrozenSet[str]] = {
    Stage.SIM: frozenset(),
    Stage.TESTED: frozenset({"unit_tests"}),
    Stage.INTEGRATED: frozenset({"unit_tests", "cross_pillar_receipt"}),
    Stage.PRODUCTION_CLAIM: frozenset({
        "unit_tests",
        "cross_pillar_receipt",
        "ops_signoff",
        "uptime",
    }),
}


@dataclass(frozen=True)
class EvidenceReceipt:
    kind: str
    digest: str
    signer_id: str
    timestamp: float
    revoked: bool = False

    def is_valid(self, now: Optional[float] = None) -> bool:
        if self.revoked:
            return False
        if now is not None and self.timestamp > now:
            return False  # Future timestamp invalid
        return True


@dataclass(frozen=True)
class Claim:
    claim_id: str
    repository: str
    source_sha: str
    desired_stage: Stage
    evidence: FrozenSet[EvidenceReceipt]
    prerequisite_claim_ids: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class PromotionGrant:
    claim_id: str
    repository: str
    source_sha: str
    granted_stage: Stage
    proof_receipt_digest: str
    not_after: float
    mac: str

    def fingerprint(self) -> str:
        payload = {
            "claim_id": self.claim_id,
            "granted_stage": self.granted_stage.value,
            "mac": self.mac,
            "not_after": self.not_after,
            "proof_receipt_digest": self.proof_receipt_digest,
            "repository": self.repository,
            "source_sha": self.source_sha,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class ClaimPromotionFenceEngine:
    """Core evidence-bound stage gate and promotion authority engine."""

    def __init__(self, authority_secret: bytes, default_ttl_s: float = 3600.0) -> None:
        if not authority_secret:
            raise ValueError("Authority secret must be non-empty")
        if default_ttl_s <= 0:
            raise ValueError("TTL must be positive")
        self._secret = authority_secret
        self._ttl = default_ttl_s
        self._promoted_registry: Dict[str, Stage] = {}
        self._revoked_digests: Set[str] = set()

    def revoke_receipt(self, receipt_digest: str) -> None:
        """Revokes an evidence receipt digest globally."""
        self._revoked_digests.add(receipt_digest)

    def evaluate_max_stage(
        self,
        receipts: Iterable[EvidenceReceipt],
        required_quorum: int = 1,
        now: Optional[float] = None,
    ) -> Stage:
        """Determines the maximum achievable stage given valid, quorum-verified receipts."""
        current_time = time.time() if now is None else now
        valid_receipts = [
            r for r in receipts
            if r.digest not in self._revoked_digests and r.is_valid(current_time)
        ]

        # Group by kind and check quorum of unique signers
        evidence_counts: Dict[str, Set[str]] = {}
        for r in valid_receipts:
            evidence_counts.setdefault(r.kind, set()).add(r.signer_id)

        present_kinds = {
            kind for kind, signers in evidence_counts.items()
            if len(signers) >= required_quorum
        }

        best = Stage.SIM
        for stage in Stage:
            required = _REQUIRED_EVIDENCE[stage]
            if required.issubset(present_kinds) and _RANK[stage] > _RANK[best]:
                best = stage
        return best

    def evaluate_claim_promotion(
        self,
        claim: Claim,
        required_quorum: int = 1,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], Stage]:
        """Evaluates whether a claim can promote to its desired stage.

        Fail-closed: checks dependencies, evidence presence, quorum, and stage ceiling.
        """
        current_time = time.time() if now is None else now

        # 1. Dependency check
        for prereq_id in claim.prerequisite_claim_ids:
            prereq_stage = self._promoted_registry.get(prereq_id)
            if not prereq_stage or _RANK[prereq_stage] < _RANK[claim.desired_stage]:
                return (
                    False,
                    f"PREREQUISITE_UNSATISFIED_{prereq_id}_NEED_{claim.desired_stage.value}",
                    Stage.SIM,
                )

        # 2. Maximum stage evaluation
        max_achievable = self.evaluate_max_stage(
            claim.evidence, required_quorum=required_quorum, now=current_time
        )

        if _RANK[claim.desired_stage] <= _RANK[max_achievable]:
            return True, None, claim.desired_stage

        return (
            False,
            f"INSUFFICIENT_EVIDENCE_HAVE_{max_achievable.value}_NEED_{claim.desired_stage.value}",
            max_achievable,
        )

    def issue_promotion_grant(
        self,
        claim: Claim,
        required_quorum: int = 1,
        now: Optional[float] = None,
    ) -> PromotionGrant:
        """Issues an HMAC-signed promotion grant if evidence and dependencies pass."""
        t_now = time.time() if now is None else now
        ok, reason, achieved_stage = self.evaluate_claim_promotion(
            claim, required_quorum=required_quorum, now=t_now
        )
        if not ok:
            raise PermissionError(f"Claim promotion denied: {reason}")

        # Compute deterministic proof receipt digest across all evidence digests
        sorted_digests = sorted([e.digest for e in claim.evidence])
        proof_payload = f"{claim.claim_id}:{claim.source_sha}:" + ",".join(sorted_digests)
        proof_digest = hashlib.sha256(proof_payload.encode()).hexdigest()

        not_after = t_now + self._ttl
        mac_body = f"{claim.claim_id}|{claim.repository}|{claim.source_sha}|{achieved_stage.value}|{proof_digest}|{not_after}"
        mac = hmac.new(self._secret, mac_body.encode(), hashlib.sha256).hexdigest()

        # Update promoted registry
        self._promoted_registry[claim.claim_id] = achieved_stage

        return PromotionGrant(
            claim_id=claim.claim_id,
            repository=claim.repository,
            source_sha=claim.source_sha,
            granted_stage=achieved_stage,
            proof_receipt_digest=proof_digest,
            not_after=not_after,
            mac=mac,
        )

    def verify_promotion_grant(
        self,
        grant: PromotionGrant,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verifies HMAC signature and expiration for a grant."""
        t_now = time.time() if now is None else now
        if t_now > grant.not_after:
            return False, "GRANT_EXPIRED"

        mac_body = f"{grant.claim_id}|{grant.repository}|{grant.source_sha}|{grant.granted_stage.value}|{grant.proof_receipt_digest}|{grant.not_after}"
        expected_mac = hmac.new(self._secret, mac_body.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_mac, grant.mac):
            return False, "BAD_HMAC_SIGNATURE"

        return True, None
