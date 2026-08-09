const RANK = { SIM: 0, TESTED: 1, INTEGRATED: 2, PRODUCTION_CLAIM: 3 };
const REQUIRED = {
  SIM: [],
  TESTED: ["unit_tests"],
  INTEGRATED: ["unit_tests", "cross_pillar_receipt"],
  PRODUCTION_CLAIM: ["unit_tests", "cross_pillar_receipt", "ops_signoff", "uptime"],
};
export function maxStage(evidence) {
  const kinds = new Set(evidence);
  let best = "SIM";
  for (const stage of Object.keys(REQUIRED)) {
    if (REQUIRED[stage].every(k => kinds.has(k)) && RANK[stage] > RANK[best]) best = stage;
  }
  return best;
}
export function allowClaim(evidence, desired) {
  const mx = maxStage(evidence);
  if (RANK[desired] <= RANK[mx]) return { ok: true, reason: null };
  return { ok: false, reason: `HAVE_${mx}_NEED_${desired}` };
}
