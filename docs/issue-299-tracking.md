# Issue #299 tracking note

This pull request tracks the requested registration-retry work for
[#299](https://github.com/harpocrates-stellar/main/issues/299).

The existing registration boundary is idempotent: retries reuse the canonical
video/proof/transaction identity and conflicting payloads remain rejected.
Further frontend retry wiring can be reviewed and extended from this branch
without introducing a second registration protocol.
