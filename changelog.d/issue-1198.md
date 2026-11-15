### Added
- Index registered proofs by identity tier and bind `list_proofs_by_tier` pagination cursors (`TierProofCursor`) to the selected tier so cross-tier cursor reuse fails closed with `InvalidCursor` (#1198).
