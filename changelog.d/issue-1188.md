### Added

- Exposed pure read-only role invitation expiry inspection (`get_admin_invitation_status` and `get_role_invitation_status`) returning consistent `Nonexistent`, `Active`, and `Expired` states without mutating contract storage or emitting hidden cleanup events (#1188).
