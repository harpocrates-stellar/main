# Redacted-Derivative-of-Registered-Evidence Proof — Implementation Plan

## Status

Planning scaffold for: `feat(zk): prove that a redacted derivative originates
from registered evidence`. No circuit, contract, backend, or frontend code
has been written yet. This document exists to scope the work before
implementation begins in `zk/noir/redaction_lineage` and its integration
points, following the pattern established by `silent_witness` and
`selective_disclosure`.

## Relationship to existing lineage work

`backend/lineage.py` and `frontend/src/lineageManifest.ts` already implement
**unauthenticated** lineage metadata: a `TransformationManifest` records
`parentProofIds`, `operationType`, `parametersDigest`, and `outputDigest`,
but nothing today proves in zero knowledge that the output digest was
actually produced from the parent evidence under the claimed operation. This
feature adds that missing cryptographic binding, reusing the manifest shape
and graph-validation rules in `validate_lineage_graph()` rather than
introducing a parallel lineage representation.

## Open design questions to resolve before circuit code is written

1. Public inputs: which of the existing `hpx-vi/1` frame conventions
   (`docs/zk-conformance-vectors.md`) extend cleanly to a redaction proof —
   parent commitment, output commitment, operation-policy id, and a
   `redaction_witness/v1` frame — versus what must stay private (original
   frames/pixels, removed regions, transformation parameters).
2. Allowed-operation policy: how `crop` / `blur` / `redact` / `compose`
   (per `LINEAGE_IMPLEMENTATION.md`) map to bounded, circuit-checkable
   commitments over chunked media rather than whole-file constraints.
3. Parent-proof binding: how the proof ties back to a `silent_witness` (or
   lineage-registered) parent without re-deriving `credential_root`.
4. Where verification lives short-term: local/browser verification first,
   Soroban `HarpocratesRegistry` verifier wiring planned but out of scope for
   default-on release (per issue's "publish benchmarks before enabling by
   default").

## Phasing

- Phase 0 (this doc): scope, threat-model delta, public/private input table.
- Phase 1: Noir prototype circuit + unit tests (`nargo test`) + adversarial
  vectors (crop substitution, reordered chunks, altered visible regions,
  wrong parent, replay, malformed proof).
- Phase 2: cross-layer conformance codec entry (backend, browser, contract)
  following `docs/zk-conformance-vectors.md`'s one-codec-three-layers model.
- Phase 3: backend endpoint + browser proving integration + artifact
  versioning.
- Phase 4: Soroban verification planning doc (not full deployment — see
  issue's out-of-scope section).
- Phase 5: security docs (assumptions, unsupported transformations),
  benchmarks (`docs/zk-benchmarks.md` pattern), witness zeroization tests.

See the accompanying VSCode implementation prompt for the detailed,
per-phase task breakdown.
