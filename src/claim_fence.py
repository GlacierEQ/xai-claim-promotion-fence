"""Claim promotion fence — stage-gated xAI-domain claims."""
from __future__ import annotations

from enum import Enum
from typing import Iterable


class Stage(str, Enum):
    SIM = "SIM"
    TESTED = "TESTED"
    INTEGRATED = "INTEGRATED"
    PRODUCTION_CLAIM = "PRODUCTION_CLAIM"


_RANK = {Stage.SIM: 0, Stage.TESTED: 1, Stage.INTEGRATED: 2, Stage.PRODUCTION_CLAIM: 3}

_REQUIRED = {
    Stage.SIM: set(),
    Stage.TESTED: {"unit_tests"},
    Stage.INTEGRATED: {"unit_tests", "cross_pillar_receipt"},
    Stage.PRODUCTION_CLAIM: {"unit_tests", "cross_pillar_receipt", "ops_signoff", "uptime"},
}


def max_stage(evidence: Iterable[str]) -> Stage:
    kinds = set(evidence)
    best = Stage.SIM
    for stage in Stage:
        need = _REQUIRED[stage]
        if need <= kinds and _RANK[stage] > _RANK[best]:
            best = stage
    return best


def allow_claim(evidence: Iterable[str], desired: Stage) -> tuple[bool, str | None]:
    mx = max_stage(evidence)
    if _RANK[desired] <= _RANK[mx]:
        return True, None
    return False, f"HAVE_{mx.value}_NEED_{desired.value}"
