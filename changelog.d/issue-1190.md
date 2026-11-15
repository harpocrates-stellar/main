### Added

- Reject conflicting institutional role transitions queued for the same authority revision via `get_authority_revision`, `queue_admin_transfer`, `queue_role_transition`, `AuthorityRevisionMismatch` (`#113`), and `ConflictingQueuedTransition` (`#114`) while preserving already-queued compatible transitions (#1190).
