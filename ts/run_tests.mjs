import assert from "node:assert/strict";
import {
  POLICY_FINGERPRINT,
  allowClaim,
  evaluateClaim,
  evaluateMaxStage,
  maxStage,
} from "./claim_fence.mjs";

const d = char => char.repeat(64);
const claim = {
  claim_id: "claim-1",
  repository: "GlacierEQ/repo",
  source_sha: "sha-1",
  desired_stage: "INTEGRATED",
};
const receipt = (kind, digestChar, overrides = {}) => ({
  kind,
  digest: d(digestChar),
  signer_id: "signer-1",
  timestamp: 100,
  claim_id: "claim-1",
  repository: "GlacierEQ/repo",
  source_sha: "sha-1",
  revoked: false,
  ...overrides,
});

assert.equal(maxStage([]), "SIM");
assert.equal(allowClaim([], "PRODUCTION_CLAIM").ok, false);
assert.equal(maxStage(["unit_tests", "cross_pillar_receipt"]), "INTEGRATED");

const scoped = [receipt("unit_tests", "a"), receipt("cross_pillar_receipt", "b")];
const decision = evaluateClaim(scoped, claim, { now: 110 });
assert.equal(decision.ok, true);
assert.equal(decision.maxStage, "INTEGRATED");
assert.equal(decision.policyFingerprint, POLICY_FINGERPRINT);
assert.equal(decision.evidenceFingerprints.length, 2);
assert.equal(decision.fingerprint.length, 64);

const unrelated = [
  receipt("unit_tests", "c", { claim_id: "other" }),
  receipt("cross_pillar_receipt", "d", { repository: "GlacierEQ/other" }),
];
const unrelatedDecision = evaluateClaim(unrelated, { ...claim, desired_stage: "TESTED" }, { now: 110 });
assert.equal(unrelatedDecision.ok, false);
assert.equal(unrelatedDecision.maxStage, "SIM");
assert.equal(unrelatedDecision.evidenceFingerprints.length, 0);

const future = [receipt("unit_tests", "e", { timestamp: 120 })];
assert.equal(
  evaluateClaim(future, { ...claim, desired_stage: "TESTED" }, { now: 110 }).maxStage,
  "SIM",
);

const revoked = [receipt("unit_tests", "f")];
assert.equal(
  evaluateClaim(revoked, { ...claim, desired_stage: "TESTED" }, { now: 110, revokedDigests: [d("f")] }).maxStage,
  "SIM",
);

const oneSigner = [
  receipt("unit_tests", "1", { signer_id: "s1" }),
  receipt("unit_tests", "2", { signer_id: "s1" }),
];
assert.equal(
  evaluateMaxStage(oneSigner, { ...claim, desired_stage: "TESTED" }, { now: 110, requiredQuorum: 2 }).maxStage,
  "SIM",
);

const twoSigners = [
  receipt("unit_tests", "3", { signer_id: "s1" }),
  receipt("unit_tests", "4", { signer_id: "s2" }),
];
assert.equal(
  evaluateMaxStage(twoSigners, { ...claim, desired_stage: "TESTED" }, { now: 110, requiredQuorum: 2 }).maxStage,
  "TESTED",
);

const reordered = evaluateClaim([...scoped].reverse(), claim, { now: 110 });
assert.equal(decision.fingerprint, reordered.fingerprint);
assert.deepEqual(decision.evidenceFingerprints, reordered.evidenceFingerprints);

assert.throws(
  () => evaluateClaim(scoped, claim, { now: 110, requiredQuorum: 0 }),
  /positive integer/,
);
assert.throws(
  () => evaluateClaim(scoped, claim, { now: Number.NaN }),
  /now must be finite/,
);
assert.throws(
  () => evaluateClaim([{ ...receipt("unit_tests", "a"), digest: "bad" }], claim, { now: 110 }),
  /sha256/,
);
assert.throws(
  () => evaluateClaim([{ ...receipt("unit_tests", "a"), timestamp: Number.POSITIVE_INFINITY }], claim, { now: 110 }),
  /timestamp must be finite/,
);

console.log("ok");
