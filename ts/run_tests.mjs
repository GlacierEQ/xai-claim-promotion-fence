import { maxStage, allowClaim } from "./claim_fence.mjs";
import assert from "node:assert/strict";
assert.equal(maxStage([]), "SIM");
assert.equal(allowClaim([], "PRODUCTION_CLAIM").ok, false);
assert.equal(maxStage(["unit_tests", "cross_pillar_receipt"]), "INTEGRATED");
console.log("ok");
