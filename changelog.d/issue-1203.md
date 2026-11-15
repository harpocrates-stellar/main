### Added

- Add bounded proof-history queries (`get_proof_history` and `get_proof_history_page`) returning `ProofHistoryPage` with explicit completeness, truncation, next-page offset, and immediate-predecessor metadata so partial lifecycle pages are never presented as complete evidence histories (#1203).
