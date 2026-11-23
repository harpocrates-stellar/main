### Added

- Expose a proof's first effective revocation ledger through the additive
  `get_proof_status_details` query. Preserve the original ledger across later
  queries and repeated revocations, and report unknown ledgers for legacy
  revoked proofs without changing their statement identity (#1200).
