"""Claim promotion fence — scoped evidence, active dependencies, bounded grants.

This reference mechanism limits a claim's maturity to evidence that is explicitly
bound to the same claim ID, repository, and source SHA. Promotion grants are
short-lived proof objects; prerequisite claims count only while their grants
remain valid. This does not create production-control authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import FrozenSet, Iterable, Mapping


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _validate_token(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a non-empty machine-safe token")


def _validate_digest(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase sha256 hex digest")


def _finite_number(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field_name} must be a finite number")
    return number


class Stage(str, Enum):
    SIM = "SIM"
    TESTED = "TESTED"
    INTEGRATED = "INTEGRATED"
    PRODUCTION_CLAIM = "PRODUCTION_CLAIM"


_RANK: Mapping[Stage, int] = MappingProxyType(
    {
        Stage.SIM: 0,
        Stage.TESTED: 1,
        Stage.INTEGRATED: 2,
        Stage.PRODUCTION_CLAIM: 3,
    }
)
_REQUIRED_EVIDENCE: Mapping[Stage, FrozenSet[str]] = MappingProxyType(
    {
        Stage.SIM: frozenset(),
        Stage.TESTED: frozenset({"unit_tests"}),
        Stage.INTEGRATED: frozenset({"unit_tests", "cross_pillar_receipt"}),
        Stage.PRODUCTION_CLAIM: frozenset(
            {"unit_tests", "cross_pillar_receipt", "ops_signoff", "uptime"}
        ),
    }
)

POLICY_FINGERPRINT = digest(
    {
        "stage_rank": {stage.value: rank for stage, rank in _RANK.items()},
        "required_evidence": {
            stage.value: sorted(kinds)
            for stage, kinds in _REQUIRED_EVIDENCE.items()
        },
        "scope": "claim_id+repository+source_sha",
        "quorum": "unique_signers_per_evidence_kind",
        "dependencies": "active_verified_prerequisite_grants",
    }
)


@dataclass(frozen=True)
class EvidenceReceipt:
    kind: str
    digest: str
    signer_id: str
    timestamp: float
    claim_id: str
    repository: str
    source_sha: str
    revoked: bool = False

    def __post_init__(self) -> None:
        _validate_token(self.kind, "evidence kind")
        _validate_digest(self.digest, "evidence digest")
        _validate_token(self.signer_id, "signer_id")
        _validate_token(self.claim_id, "claim_id")
        _validate_token(self.repository, "repository")
        _validate_token(self.source_sha, "source_sha")
        object.__setattr__(self, "timestamp", _finite_number(self.timestamp, "timestamp"))
        if not isinstance(self.revoked, bool):
            raise ValueError("revoked must be boolean")

    def fingerprint(self) -> str:
        return digest(
            {
                "kind": self.kind,
                "digest": self.digest,
                "signer_id": self.signer_id,
                "timestamp": self.timestamp,
                "claim_id": self.claim_id,
                "repository": self.repository,
                "source_sha": self.source_sha,
                "revoked": self.revoked,
            }
        )

    def is_valid_for(self, claim: "Claim", now: float, revoked_digests: set[str]) -> bool:
        return (
            not self.revoked
            and self.digest not in revoked_digests
            and self.timestamp <= now
            and self.claim_id == claim.claim_id
            and self.repository == claim.repository
            and self.source_sha == claim.source_sha
        )


@dataclass(frozen=True)
class Claim:
    claim_id: str
    repository: str
    source_sha: str
    desired_stage: Stage
    evidence: FrozenSet[EvidenceReceipt]
    prerequisite_claim_ids: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        _validate_token(self.claim_id, "claim_id")
        _validate_token(self.repository, "repository")
        _validate_token(self.source_sha, "source_sha")
        if not isinstance(self.desired_stage, Stage):
            raise ValueError("desired_stage must be Stage")
        if not isinstance(self.evidence, frozenset):
            raise ValueError("evidence must be a frozenset")
        if not isinstance(self.prerequisite_claim_ids, frozenset):
            raise ValueError("prerequisite_claim_ids must be a frozenset")
        for prereq_id in self.prerequisite_claim_ids:
            _validate_token(prereq_id, "prerequisite claim id")
        if self.claim_id in self.prerequisite_claim_ids:
            raise ValueError("claim cannot depend on itself")

    def identity_fingerprint(self) -> str:
        return digest(
            {
                "claim_id": self.claim_id,
                "repository": self.repository,
                "source_sha": self.source_sha,
                "desired_stage": self.desired_stage.value,
                "prerequisite_claim_ids": sorted(self.prerequisite_claim_ids),
            }
        )


@dataclass(frozen=True)
class PromotionDecision:
    allowed: bool
    reason: str | None
    desired_stage: Stage
    max_achievable_stage: Stage
    claim_fingerprint: str
    policy_fingerprint: str
    evidence_fingerprints: tuple[str, ...]
    prerequisite_grant_fingerprints: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True)
class PromotionGrant:
    claim_id: str
    repository: str
    source_sha: str
    granted_stage: Stage
    claim_fingerprint: str
    policy_fingerprint: str
    evidence_fingerprints: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    prerequisite_grant_fingerprints: tuple[str, ...]
    not_after: float
    mac: str

    def signed_payload(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "repository": self.repository,
            "source_sha": self.source_sha,
            "granted_stage": self.granted_stage.value,
            "claim_fingerprint": self.claim_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "evidence_fingerprints": list(self.evidence_fingerprints),
            "evidence_digests": list(self.evidence_digests),
            "prerequisite_grant_fingerprints": list(
                self.prerequisite_grant_fingerprints
            ),
            "not_after": self.not_after,
        }

    def fingerprint(self) -> str:
        return digest({"payload": self.signed_payload(), "mac": self.mac})


class ClaimPromotionFenceEngine:
    """Evidence-bound stage gate and short-lived claim-promotion proof engine."""

    def __init__(self, authority_secret: bytes, default_ttl_s: float = 3600.0) -> None:
        if not isinstance(authority_secret, bytes) or not authority_secret:
            raise ValueError("authority_secret must be non-empty bytes")
        ttl = _finite_number(default_ttl_s, "default_ttl_s")
        if ttl <= 0:
            raise ValueError("default_ttl_s must be positive")
        self._secret = authority_secret
        self._ttl = ttl
        self._promoted_registry: dict[str, PromotionGrant] = {}
        self._revoked_digests: set[str] = set()
        self._revoked_grants: set[str] = set()

    def revoke_receipt(self, receipt_digest: str) -> None:
        _validate_digest(receipt_digest, "receipt_digest")
        self._revoked_digests.add(receipt_digest)

    def revoke_grant(self, grant_fingerprint: str) -> None:
        _validate_digest(grant_fingerprint, "grant_fingerprint")
        self._revoked_grants.add(grant_fingerprint)

    @staticmethod
    def _validate_quorum(required_quorum: int) -> int:
        if isinstance(required_quorum, bool) or not isinstance(required_quorum, int):
            raise ValueError("required_quorum must be a positive integer")
        if required_quorum <= 0:
            raise ValueError("required_quorum must be a positive integer")
        return required_quorum

    @staticmethod
    def _now(now: float | None) -> float:
        return _finite_number(time.time() if now is None else now, "now")

    def _valid_scoped_receipts(
        self, claim: Claim, now: float
    ) -> tuple[EvidenceReceipt, ...]:
        valid = [
            receipt
            for receipt in claim.evidence
            if receipt.is_valid_for(claim, now, self._revoked_digests)
        ]
        return tuple(
            sorted(
                valid,
                key=lambda receipt: (
                    receipt.kind,
                    receipt.signer_id,
                    receipt.digest,
                    receipt.timestamp,
                ),
            )
        )

    def evaluate_max_stage(
        self,
        claim: Claim,
        required_quorum: int = 1,
        now: float | None = None,
    ) -> tuple[Stage, tuple[EvidenceReceipt, ...]]:
        quorum = self._validate_quorum(required_quorum)
        current_time = self._now(now)
        valid_receipts = self._valid_scoped_receipts(claim, current_time)

        evidence_signers: dict[str, set[str]] = {}
        for receipt in valid_receipts:
            evidence_signers.setdefault(receipt.kind, set()).add(receipt.signer_id)
        present_kinds = {
            kind
            for kind, signers in evidence_signers.items()
            if len(signers) >= quorum
        }

        best = Stage.SIM
        for stage in Stage:
            if (
                _REQUIRED_EVIDENCE[stage].issubset(present_kinds)
                and _RANK[stage] > _RANK[best]
            ):
                best = stage
        return best, valid_receipts

    def verify_promotion_grant(
        self,
        grant: PromotionGrant,
        now: float | None = None,
    ) -> tuple[bool, str | None]:
        current_time = self._now(now)
        if not isinstance(grant, PromotionGrant):
            return False, "MALFORMED_GRANT"
        try:
            _validate_token(grant.claim_id, "grant claim_id")
            _validate_token(grant.repository, "grant repository")
            _validate_token(grant.source_sha, "grant source_sha")
            _validate_digest(grant.claim_fingerprint, "grant claim_fingerprint")
            _validate_digest(grant.policy_fingerprint, "grant policy_fingerprint")
            not_after = _finite_number(grant.not_after, "grant not_after")
            for value in grant.evidence_fingerprints:
                _validate_digest(value, "evidence fingerprint")
            for value in grant.evidence_digests:
                _validate_digest(value, "evidence digest")
            for value in grant.prerequisite_grant_fingerprints:
                _validate_digest(value, "prerequisite grant fingerprint")
        except ValueError:
            return False, "MALFORMED_GRANT"

        if grant.policy_fingerprint != POLICY_FINGERPRINT:
            return False, "POLICY_MISMATCH"
        grant_fp = grant.fingerprint()
        if grant_fp in self._revoked_grants:
            return False, "GRANT_REVOKED"
        if current_time > not_after:
            return False, "GRANT_EXPIRED"
        if any(value in self._revoked_digests for value in grant.evidence_digests):
            return False, "EVIDENCE_REVOKED"
        if any(value in self._revoked_grants for value in grant.prerequisite_grant_fingerprints):
            return False, "PREREQUISITE_GRANT_REVOKED"

        expected_mac = hmac.new(
            self._secret,
            canonical_json(grant.signed_payload()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_mac, grant.mac):
            return False, "BAD_HMAC_SIGNATURE"
        return True, None

    def _active_prerequisites(
        self,
        claim: Claim,
        now: float,
    ) -> tuple[bool, str | None, tuple[str, ...]]:
        fingerprints: list[str] = []
        for prereq_id in sorted(claim.prerequisite_claim_ids):
            grant = self._promoted_registry.get(prereq_id)
            if grant is None:
                return False, f"PREREQUISITE_MISSING_{prereq_id}", ()
            valid, reason = self.verify_promotion_grant(grant, now=now)
            if not valid:
                return False, f"PREREQUISITE_INVALID_{prereq_id}_{reason}", ()
            if _RANK[grant.granted_stage] < _RANK[claim.desired_stage]:
                return (
                    False,
                    f"PREREQUISITE_STAGE_{prereq_id}_HAVE_{grant.granted_stage.value}_NEED_{claim.desired_stage.value}",
                    (),
                )
            fingerprints.append(grant.fingerprint())
        return True, None, tuple(fingerprints)

    def evaluate_claim_promotion(
        self,
        claim: Claim,
        required_quorum: int = 1,
        now: float | None = None,
    ) -> PromotionDecision:
        current_time = self._now(now)
        self._validate_quorum(required_quorum)
        prerequisites_ok, prereq_reason, prereq_fps = self._active_prerequisites(
            claim, current_time
        )
        max_stage, valid_receipts = self.evaluate_max_stage(
            claim, required_quorum=required_quorum, now=current_time
        )
        reason: str | None = prereq_reason
        allowed = prerequisites_ok and _RANK[claim.desired_stage] <= _RANK[max_stage]
        if reason is None and not allowed:
            reason = (
                f"INSUFFICIENT_EVIDENCE_HAVE_{max_stage.value}_"
                f"NEED_{claim.desired_stage.value}"
            )
        evidence_fps = tuple(receipt.fingerprint() for receipt in valid_receipts)
        claim_fp = claim.identity_fingerprint()
        payload = {
            "allowed": allowed,
            "reason": reason,
            "desired_stage": claim.desired_stage.value,
            "max_achievable_stage": max_stage.value,
            "claim_fingerprint": claim_fp,
            "policy_fingerprint": POLICY_FINGERPRINT,
            "evidence_fingerprints": list(evidence_fps),
            "prerequisite_grant_fingerprints": list(prereq_fps),
        }
        return PromotionDecision(
            allowed,
            reason,
            claim.desired_stage,
            max_stage,
            claim_fp,
            POLICY_FINGERPRINT,
            evidence_fps,
            prereq_fps,
            digest(payload),
        )

    def issue_promotion_grant(
        self,
        claim: Claim,
        required_quorum: int = 1,
        now: float | None = None,
    ) -> PromotionGrant:
        current_time = self._now(now)
        decision = self.evaluate_claim_promotion(
            claim, required_quorum=required_quorum, now=current_time
        )
        if not decision.allowed:
            raise PermissionError(f"Claim promotion denied: {decision.reason}")
        valid_receipts = self._valid_scoped_receipts(claim, current_time)
        evidence_digests = tuple(sorted(receipt.digest for receipt in valid_receipts))
        not_after = current_time + self._ttl
        unsigned = PromotionGrant(
            claim_id=claim.claim_id,
            repository=claim.repository,
            source_sha=claim.source_sha,
            granted_stage=claim.desired_stage,
            claim_fingerprint=decision.claim_fingerprint,
            policy_fingerprint=POLICY_FINGERPRINT,
            evidence_fingerprints=decision.evidence_fingerprints,
            evidence_digests=evidence_digests,
            prerequisite_grant_fingerprints=decision.prerequisite_grant_fingerprints,
            not_after=not_after,
            mac="",
        )
        mac = hmac.new(
            self._secret,
            canonical_json(unsigned.signed_payload()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        grant = PromotionGrant(**{**unsigned.__dict__, "mac": mac})

        existing = self._promoted_registry.get(claim.claim_id)
        if existing is not None:
            same_identity = (
                existing.claim_id == grant.claim_id
                and existing.repository == grant.repository
                and existing.source_sha == grant.source_sha
            )
            if not same_identity:
                raise ValueError("claim_id is already bound to a different claim identity")
            if _RANK[grant.granted_stage] < _RANK[existing.granted_stage]:
                raise ValueError("promotion registry cannot move claim stage backward")
        self._promoted_registry[claim.claim_id] = grant
        return grant


def max_stage(evidence_kinds: Iterable[str]) -> Stage:
    """Legacy label-only helper; not a scoped-evidence promotion authority."""
    kinds = set(evidence_kinds)
    if any(not isinstance(kind, str) or not kind for kind in kinds):
        raise ValueError("evidence kinds must be non-empty strings")
    best = Stage.SIM
    for stage in Stage:
        if _REQUIRED_EVIDENCE[stage].issubset(kinds) and _RANK[stage] > _RANK[best]:
            best = stage
    return best


def allow_claim(evidence_kinds: Iterable[str], desired: Stage) -> tuple[bool, str | None]:
    """Legacy label-only helper; use ClaimPromotionFenceEngine for proof authority."""
    if not isinstance(desired, Stage):
        raise ValueError("desired must be Stage")
    maximum = max_stage(evidence_kinds)
    if _RANK[desired] <= _RANK[maximum]:
        return True, None
    return False, f"HAVE_{maximum.value}_NEED_{desired.value}"
