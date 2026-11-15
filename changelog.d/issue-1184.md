### Security

- Bound queued privileged transitions (`propose_admin`, `propose_timelocked_action`, and `propose_council_action`) to canonical domain-separated on-chain role-change intent digests and enforced execution-time target-role and parameter verification (`RoleIntentDigestMismatch` `#113`) (#1184).
