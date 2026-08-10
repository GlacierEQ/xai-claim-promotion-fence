import crypto from "node:crypto";

export const Stage = {
  SIM: "SIM",
  TESTED: "TESTED",
  INTEGRATED: "INTEGRATED",
  PRODUCTION_CLAIM: "PRODUCTION_CLAIM",
};

const RANK = { SIM: 0, TESTED: 1, INTEGRATED: 2, PRODUCTION_CLAIM: 3 };
const REQUIRED = {
  SIM: [],
  TESTED: ["unit_tests"],
  INTEGRATED: ["unit_tests", "cross_pillar_receipt"],
  PRODUCTION_CLAIM: ["unit_tests", "cross_pillar_receipt", "ops_signoff", "uptime"],
};
const TOKEN = /^[A-Za-z0-9_.:/-]+$/;
const DIGEST = /^[0-9a-f]{64}$/;

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function fingerprint(value) {
  return crypto.createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

export const POLICY_FINGERPRINT = fingerprint({
  stage_rank: RANK,
  required_evidence: REQUIRED,
  scope: "claim_id+repository+source_sha",
  quorum: "unique_signers_per_evidence_kind",
  dependencies: "active_verified_prerequisite_grants",
});

function validateToken(value, name) {
  if (typeof value !== "string" || !TOKEN.test(value)) throw new Error(`${name} must be a non-empty machine-safe token`);
}

function validateQuorum(value) {
  if (!Number.isInteger(value) || value <= 0) throw new Error("requiredQuorum must be a positive integer");
}

function validateClaim(claim) {
  if (!claim || typeof claim !== "object" || Array.isArray(claim)) throw new Error("claim must be an object");
  validateToken(claim.claim_id, "claim_id");
  validateToken(claim.repository, "repository");
  validateToken(claim.source_sha, "source_sha");
  if (!(claim.desired_stage in RANK)) throw new Error("unknown desired_stage");
}

function validateReceipt(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) throw new Error("receipt must be an object");
  validateToken(receipt.kind, "receipt kind");
  if (typeof receipt.digest !== "string" || !DIGEST.test(receipt.digest)) throw new Error("receipt digest must be lowercase sha256 hex");
  validateToken(receipt.signer_id, "signer_id");
  validateToken(receipt.claim_id, "receipt claim_id");
  validateToken(receipt.repository, "receipt repository");
  validateToken(receipt.source_sha, "receipt source_sha");
  if (!Number.isFinite(receipt.timestamp)) throw new Error("receipt timestamp must be finite");
  if (typeof receipt.revoked !== "boolean") throw new Error("receipt revoked must be boolean");
}

function receiptFingerprint(receipt) {
  return fingerprint({
    kind: receipt.kind,
    digest: receipt.digest,
    signer_id: receipt.signer_id,
    timestamp: receipt.timestamp,
    claim_id: receipt.claim_id,
    repository: receipt.repository,
    source_sha: receipt.source_sha,
    revoked: receipt.revoked,
  });
}

export function evaluateMaxStage(receipts, claim, { requiredQuorum = 1, now = 0, revokedDigests = [] } = {}) {
  validateClaim(claim);
  validateQuorum(requiredQuorum);
  if (!Number.isFinite(now)) throw new Error("now must be finite");
  const revoked = new Set(revokedDigests);
  const valid = [];
  for (const receipt of receipts) {
    validateReceipt(receipt);
    if (receipt.revoked || revoked.has(receipt.digest) || receipt.timestamp > now) continue;
    if (receipt.claim_id !== claim.claim_id || receipt.repository !== claim.repository || receipt.source_sha !== claim.source_sha) continue;
    valid.push(receipt);
  }
  valid.sort((a, b) => {
    const ak = [a.kind, a.signer_id, a.digest, String(a.timestamp)].join("\u0000");
    const bk = [b.kind, b.signer_id, b.digest, String(b.timestamp)].join("\u0000");
    return ak.localeCompare(bk);
  });
  const signersByKind = new Map();
  for (const receipt of valid) {
    if (!signersByKind.has(receipt.kind)) signersByKind.set(receipt.kind, new Set());
    signersByKind.get(receipt.kind).add(receipt.signer_id);
  }
  const present = new Set(
    [...signersByKind.entries()]
      .filter(([, signers]) => signers.size >= requiredQuorum)
      .map(([kind]) => kind),
  );
  let best = "SIM";
  for (const stage of Object.keys(REQUIRED)) {
    if (REQUIRED[stage].every(kind => present.has(kind)) && RANK[stage] > RANK[best]) best = stage;
  }
  return {
    maxStage: best,
    evidenceFingerprints: valid.map(receiptFingerprint),
    policyFingerprint: POLICY_FINGERPRINT,
  };
}

export function evaluateClaim(receipts, claim, options = {}) {
  validateClaim(claim);
  const result = evaluateMaxStage(receipts, claim, options);
  const allowed = RANK[claim.desired_stage] <= RANK[result.maxStage];
  const reason = allowed ? null : `INSUFFICIENT_EVIDENCE_HAVE_${result.maxStage}_NEED_${claim.desired_stage}`;
  const payload = {
    allowed,
    reason,
    desired_stage: claim.desired_stage,
    max_achievable_stage: result.maxStage,
    claim_fingerprint: fingerprint(claim),
    policy_fingerprint: result.policyFingerprint,
    evidence_fingerprints: result.evidenceFingerprints,
  };
  return {
    allowed,
    ok: allowed,
    reason,
    maxStage: result.maxStage,
    claimFingerprint: payload.claim_fingerprint,
    policyFingerprint: result.policyFingerprint,
    evidenceFingerprints: result.evidenceFingerprints,
    fingerprint: fingerprint(payload),
  };
}

export function maxStage(evidenceKinds) {
  const kinds = new Set(evidenceKinds);
  let best = "SIM";
  for (const stage of Object.keys(REQUIRED)) {
    if (REQUIRED[stage].every(kind => kinds.has(kind)) && RANK[stage] > RANK[best]) best = stage;
  }
  return best;
}

export function allowClaim(evidenceKinds, desired) {
  if (!(desired in RANK)) throw new Error("unknown desired stage");
  const mx = maxStage(evidenceKinds);
  if (RANK[desired] <= RANK[mx]) return { ok: true, reason: null };
  return { ok: false, reason: `HAVE_${mx}_NEED_${desired}` };
}
