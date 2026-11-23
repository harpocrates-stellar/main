# Portable Lineage Verification Bundle

Harpocrates supports packaging canonical lineage ancestry statements and root
trust references into a self-contained, offline-verifiable JSON bundle with
bounded graph closure.

## Design Goals

- **Offline & fail-closed:** Verification never fetches arbitrary URLs or
  external resources. Any URL-like field or forbidden URL key (`url`, `uri`,
  `href`, `endpoint`, `fetchUrl`, `remoteUrl`) is rejected with
  `external_url_forbidden`.
- **Canonical encoding:** Statements and trust references are sorted
  deterministically and serialized with compact JSON (`sort_keys=True`,
  `separators=(",", ":")`). Identical graphs produce identical `bundleDigest`
  values.
- **Explicit trust separation:** Each root trust reference declares its
  `trustAnchorType` (`onchain_proof` or `c2pa_binding`) and identity `tier`
  (`silent`, `source`, or `seal`). C2PA bindings are never conflated with
  on-chain or ZK proof verification.
- **Privacy-safe errors:** `LineageBundleError.to_dict()` returns only stable
  `reason` codes and optional `field` names—never raw digests, media hashes, or
  actor identifiers.

## Bundle Schema (`bundleVersion = 1`)

```json
{
  "protocol": "harpocrates",
  "bundleVersion": 1,
  "targetDigest": "<64-char lowercase hex>",
  "network": "testnet",
  "statements": [
    {
      "protocol": "harpocrates",
      "version": 2,
      "parentProofIds": ["<64-char hex>"],
      "operationType": "crop",
      "parametersDigest": "<64-char hex>",
      "toolIdentity": "harpocrates-studio",
      "toolVersion": "1.2.3",
      "outputDigest": "<64-char hex>",
      "network": "testnet",
      "actorAddress": "GAJC123",
      "manifestDigest": "<64-char lowercase hex>"
    }
  ],
  "trustReferences": [
    {
      "proofId": "<64-char lowercase hex>",
      "network": "testnet",
      "contractId": "<Soroban contract ID>",
      "tier": "silent",
      "trustAnchorType": "onchain_proof"
    }
  ],
  "bundleDigest": "<64-char lowercase hex>"
}
```

## Bounds

| Constant | Default | Purpose |
|---|---|---|
| `MAX_BUNDLE_BYTES` | `131072` (128 KiB) | Maximum serialized bundle size |
| `MAX_BUNDLE_NODES` | `64` | Maximum statements in the closure |
| `MAX_BUNDLE_TRUST_REFS` | `64` | Maximum root trust references |
| `MAX_LINEAGE_DEPTH` | `4` | Maximum ancestry depth from `targetDigest` |
| `MAX_LINEAGE_FANOUT` | `4` | Maximum `parentProofIds` per statement |

## Fail-Closed Rejection Reasons

- `missing_parent`: A statement references a parent that is neither another
  statement in `statements` nor a root in `trustReferences`.
- `cycle_detected`: A direct or transitive cycle exists in the ancestry graph.
- `contradictory_root`: Duplicate/conflicting `proofId` in `trustReferences`,
  a root `proofId` also claimed as a derived statement's `outputDigest`, or a
  root whose `network` disagrees with the bundle `network`.
- `external_url_forbidden`: A URL scheme or forbidden URL key was detected.
- `depth_exceeded` / `node_limit_exceeded` / `bundle_too_large`: Graph or
  payload exceeds configured bounds.
- `bundle_digest_mismatch` / `statement_digest_mismatch`: Digest integrity
  check failed.
- `disconnected_statement` / `unused_trust_reference`: Orphaned statements or
  unreferenced trust anchors are not permitted in a closed bundle.

## Incomplete Lineage Verification (`allow_incomplete=True`)

By default (`allow_incomplete=False`), `verify_lineage_verification_bundle` fails
closed with `LineageBundleError("missing_parent", "parentProofIds")` whenever
any referenced parent is absent from `statements` and `trustReferences`.

When callers explicitly opt in with `allow_incomplete=True`, missing parent
dependencies are exposed as a distinct verification result instead of raising:

- `status`: `LineageVerificationStatus.INCOMPLETE` (`"incomplete"`) rather than
  `LineageVerificationStatus.VERIFIED` (`"verified"`).
- `valid`: `False` and `complete`: `False` — an incomplete graph is never
  presented as a fully verified original.
- `verified_edges`: deterministic tuple of `LineageVerifiedEdge` entries for
  every known verified edge (`parentKind`: `"statement"` or `"trust_reference"`).
- `missing_dependencies`: deterministic tuple of `LineageMissingDependency`
  entries listing each absent `parentId`, the sorted `referencedBy` child
  statement digests, and `reason: "missing_parent"`.

All other fail-closed checks (cycles, digest integrity, bounds, forbidden URLs,
network consistency, disconnected statements, and unused trust references)
continue to raise `LineageBundleError`.

## Python API (`backend/lineage.py`)

- `build_lineage_verification_bundle(*, target_digest, network, statements, trust_references, max_depth=MAX_LINEAGE_DEPTH, max_nodes=MAX_BUNDLE_NODES) -> dict`
- `verify_lineage_verification_bundle(bundle, *, max_depth=MAX_LINEAGE_DEPTH, max_nodes=MAX_BUNDLE_NODES, allow_incomplete=False) -> LineageBundleVerificationResult`
- `LineageVerificationStatus` (`VERIFIED`, `INCOMPLETE`), `LineageVerifiedEdge`, `LineageMissingDependency`
- `canonical_lineage_bundle(bundle) -> str`
- `lineage_bundle_digest(bundle) -> str`
- `trust_reference_from_c2pa_binding(binding, *, c2pa_digest=None) -> dict`
- `compare_lineage_graphs(before, after, *, max_depth=MAX_LINEAGE_DEPTH, max_nodes=MAX_BUNDLE_NODES) -> LineageGraphComparisonReport`
- `canonical_lineage_comparison_report(report) -> str`
- `lineage_comparison_report_digest(report) -> str`

## Deterministic Graph Comparison Report (`reportVersion = 1`)

`compare_lineage_graphs(before, after)` verifies both bundles offline (fail-closed)
before comparing their statements and root trust references by canonical digest:

- **Provenance changes (`addedAssertions`, `removedAssertions`, `changedAssertions`):**
  - Statements are keyed by canonical lowercase `outputDigest` and compared by
    `manifestDigest` and order-independent provenance digest.
  - Trust references are keyed by canonical lowercase `proofId` and compared by
    canonical SHA-256 digest, preserving identity `tier` and `trustAnchorType`
    separation.
  - `changedAssertions` reports only canonical digests and `changedFields`
    names—never raw actor identifiers or media values.
- **Ordering differences (`orderingDifferences`):**
  - Bundle-level list order differences (`scope: "statements"` or
    `"trust_references"`) and statement-level `parentProofIds` permutations
    (`scope: "statement_parents"`) are reported separately from provenance
    changes so `equivalentProvenance` remains `true` when only ordering differs.
- **Deterministic encoding:** All report collections are sorted canonically and
  sealed with `reportDigest` (`SHA-256` of `canonical_lineage_comparison_report`).
