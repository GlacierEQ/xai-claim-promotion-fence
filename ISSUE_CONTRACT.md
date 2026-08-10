# ISSUE CONTRACT
## Pain
Bounded demos or unrelated receipts can be described as stronger claims when evidence is counted only by label, when claim/source scope is missing, or when prerequisite promotions remain trusted after their evidence expires or is revoked.

## Success
- Stages remain ordered `SIM → TESTED → INTEGRATED → PRODUCTION_CLAIM`
- Every counted evidence receipt binds the exact `claim_id + repository + source_sha`
- Destination-stage evidence kinds must meet a positive quorum of unique signers
- Future, revoked, malformed, or out-of-scope receipts do not count
- Promotion decisions bind exact claim identity, policy identity, valid evidence identities, and active prerequisite grant identities
- Promotion grants are time-bounded and become invalid when supporting evidence or prerequisite grants are revoked
- A claim ID cannot be rebound to a different repository/source identity
- Python and Node preserve the same scoped evidence/quorum stage ceiling

## Boundary
This is an independent claim-governance reference mechanism. A `PRODUCTION_CLAIM` stage is evidence maturity, not production-control authority. The fence does not verify physical operations, authorize actuation, execute production systems, or claim xAI affiliation/adoption.
