#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from claim_fence import allow_claim, Stage, max_stage

def main() -> int:
    stage = max_stage(["unit_tests", "cross_pillar_receipt"]).value
    ok_int, _ = allow_claim(["unit_tests", "cross_pillar_receipt"], Stage.INTEGRATED)
    ok_prod, reason = allow_claim(["unit_tests"], Stage.PRODUCTION_CLAIM)
    out = {"max_stage": stage, "integrated_ok": ok_int, "prod_blocked": not ok_prod, "reason": reason,
           "ok": stage == "INTEGRATED" and ok_int and (not ok_prod)}
    print(json.dumps(out, sort_keys=True))
    return 0 if out["ok"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
