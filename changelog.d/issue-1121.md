### Added
- `ConsentManager.prune_expired_batch`: bounded, resumable consent cleanup that returns a `RetentionCheckpoint` (pass it back to resume after an interruption) and records a `ConsentDeletionAudit` reference for every pruned state.
