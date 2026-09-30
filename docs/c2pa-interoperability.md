# C2PA Interoperability

Harpocrates can import and export C2PA-compatible authenticity manifests.
This document describes the trust model, the canonical field mapping,
the compatibility matrix, and how to roll back.

---

## Trust model

**A C2PA claim is not a Harpocrates proof.**

The two systems have different trust anchors:

| Property | Harpocrates | C2PA |
|---|---|---|
| Integrity root | Soroban on-chain record + ZK circuit | C2PA claim generator + signing key |
| Privacy | ZK nullifier; Silent Witness tier is anonymous | Not a design goal; identity is in the claim |
| Determinism | SHA-256 canonical metadata hash, on-chain binding | Claim-generator defined |
| Verification | On-chain `get_by_video` + Noir proof | C2PA SDK signature verification |

The C2PA layer in Harpocrates is a **bounded bridge**, not a trust equivalence.
Callers must corroborate the extracted binding against on-chain records using
the standard Harpocrates verification flow before making any trust decision.

### C2paTrustStatus

All API responses and parsed manifests carry an explicit `trust_status` field.
Its values are defined to be free of on-chain terminology:

| Value | Meaning |
|---|---|
| `signature_not_checked` | Default for all imports; no crypto verification performed |
| `signature_valid` | Internal digest binding is self-consistent (no crypto) |
| `unsupported_algorithm` | Manifest references an algorithm not supported by this version |
| `binding_mismatch` | Extracted digests do not match the claimed hashes |
| `parse_failed` | Manifest could not be parsed; no trust can be assigned |

`signature_not_checked` is the only value produced by the current
implementation. The others are reserved for future signing integration.

Callers **must not** treat any C2paTrustStatus as equivalent to the
Harpocrates `confirmed` verification outcome.

---

## Field mapping — version 1

`C2PA_HARPOCRATES_MAPPING_VERSION = 1`

The mapping pins the canonical field names between Harpocrates evidence/proof
digests and C2PA assertion/claim fields.

| Harpocrates field | C2PA assertion data field | Notes |
|---|---|---|
| `videoHash` (embedded, on-chain) | `video_hash` | 32-byte hex, lowercase |
| `metadataHash` | `metadata_hash` | 32-byte hex, lowercase |
| `proofId` | `proof_id` | 32-byte hex, lowercase |
| `tier` | `tier` | `silent` \| `source` \| `seal` |
| `network` | `network` | Stellar network passphrase |
| `contractId` | `contract_id` | Soroban registry contract ID |

The binding is embedded twice: as a named assertion (`harpocrates.binding/v1`)
and as a top-level `harpocrates_binding` object, for both assertion-based and
direct consumers.

### Consistent copies

The two copies must agree. The parser validates each copy as a complete binding
and then compares them field by field; a contradiction is rejected instead of
being resolved in favour of whichever copy a consumer happens to read:

| Condition | Reject reason |
|---|---|
| The copies disagree on `video_hash`, `metadata_hash`, `proof_id`, `tier`, `network`, `contract_id`, or `mapping_version` | `embedded_binding_mismatch` (field = the first disagreeing field) |
| More than one `harpocrates.binding/v1` assertion | `embedded_binding_duplicate` |
| A copy that is not a complete, individually valid binding | `invalid_type` / `missing_key` / `invalid_value` / `mapping_version_mismatch`, with the copy's path in `field` (e.g. `assertions[0].data.proof_id`) |

Copies are compared after normalisation (hex lower-cased, text stripped), so a
manifest that differs only in hex casing or surrounding whitespace is accepted.

### Canonical JSON encoding

The manifest is always serialised with sorted keys and no trailing whitespace.
This makes the export idempotent: identical inputs produce byte-identical JSON
and an identical SHA-256 digest.

### Versioning

A mapping version bump (e.g., to version 2) requires:

1. A new `mapping_version` constant in `backend/c2pa.py` and `frontend/src/c2pa.ts`.
2. A new entry in this table.
3. Updated conformance fixtures in `backend/test_c2pa.py` and `frontend/src/c2pa.test.ts`.
4. A migration note in `MIGRATION_GUIDE.md`.
5. A re-run of all C2PA tests.

The parser rejects manifests whose `mapping_version` differs from the current
constant. This prevents silent drift between import and export.

---

## Hash verification

C2PA import performs two independent checks over the digests in a manifest.

**1. Embedded copies (always on).** The two embedded copies of the binding must
agree, per the table above. This runs on every import and needs nothing from the
caller.

**2. Submitted vs embedded (opt-in).** An exported manifest's `digest` proves
the manifest is internally consistent, but on its own it says nothing about the
evidence the caller is asking about. Supplying `expected` to
`POST /api/c2pa/import` closes that gap: the hashes the caller claims are
compared against the binding embedded in the manifest, and any disagreement is a
rejection.

| Aspect | Behaviour |
|---|---|
| Fields compared | `video_hash`, `metadata_hash`, `proof_id`, `tier`, `network`, `contract_id` — only the ones the caller supplies |
| Order | Fixed (`video_hash` → `contract_id`), independent of JSON key order, so the same submission always reports the same first mismatch |
| Normalisation | Hex is lower-cased, text is stripped; surrounding whitespace and hex casing do not cause a mismatch |
| Mismatch | `400 VALIDATION_ERROR`, `error.field` = the first mismatching field, `error.message` names the mismatching fields |
| Malformed submission | `400 VALIDATION_ERROR`, `error.message` names the offending field |
| Match | `200` with `hashes_verified: true` and `hashes_compared` listing the fields checked |
| No `expected` | `200` with `hashes_verified: false` and `hashes_compared: []` — nothing was compared |

**Trust boundary.** A match is *integrity corroboration only*. It does not make
the manifest a Harpocrates proof, does not consult Soroban, and does not verify
a ZK proof: `trust_status` stays `signature_not_checked` either way. Callers must
still corroborate the binding against on-chain records.

**Privacy.** Rejections carry the reason code and offending field *name* only.
Neither the submitted value nor the embedded value is echoed in the response or
written to logs.

For library callers, the same check is available without the HTTP layer:

```python
from c2pa import corroborate_binding, parse_c2pa_manifest

parsed = parse_c2pa_manifest(raw_manifest)
result = corroborate_binding(parsed, video_hash=registered_video_hash)
# result.ok, result.compared_fields, result.mismatches — field names only
```

---

## API reference

### `POST /api/c2pa/export`

Export a C2PA-compatible manifest from Harpocrates evidence digests.

**Request body (JSON):**

```json
{
  "video_hash":     "32-byte hex — embedded video hash",
  "metadata_hash":  "32-byte hex",
  "proof_id":       "32-byte hex",
  "tier":           "silent | source | seal",
  "network":        "Stellar network passphrase",
  "contract_id":    "Soroban registry contract ID",
  "claim_generator": "optional override"
}
```

**Response body (JSON):**

```json
{
  "ok": true,
  "manifest":      { /* C2PA-compatible manifest */ },
  "digest":        "sha256 of canonical JSON",
  "trust_status":  "signature_not_checked",
  "note":          "C2PA trust status is independent of Harpocrates on-chain and ZK verification.",
  "request_id":    "uuid"
}
```

### `POST /api/c2pa/import`

Parse and validate a C2PA-compatible manifest, optionally corroborating
caller-submitted hashes against the binding embedded in it.

**Request body (JSON):**

```json
{
  "manifest": { /* manifest object */ }
}
```

Or with a raw JSON string:

```json
{
  "manifest": "{\"claim_generator\":\"harpocrates\",...}"
}
```

Supplying `expected` turns on submitted-vs-embedded verification (see
[Hash verification](#hash-verification)). Every key is optional; unknown keys are
ignored:

```json
{
  "manifest": { /* manifest object */ },
  "expected": {
    "video_hash":    "32-byte hex — the hash the caller claims",
    "metadata_hash": "optional",
    "proof_id":      "optional",
    "tier":          "optional",
    "network":       "optional",
    "contract_id":   "optional"
  }
}
```

**Response body (JSON):**

```json
{
  "ok": true,
  "binding": {
    "mapping_version": 1,
    "video_hash":     "...",
    "metadata_hash":  "...",
    "proof_id":       "...",
    "tier":           "silent | source | seal",
    "network":        "...",
    "contract_id":    "..."
  },
  "trust_status":        "signature_not_checked",
  "hashes_verified":     true,
  "hashes_compared":     ["video_hash", "metadata_hash", "proof_id", "tier", "network", "contract_id"],
  "unknown_assertions":  [{ "label": "c2pa.actions", "unsupported_semantics": true }],
  "note":                "Corroborate this binding against on-chain records before trusting it.",
  "request_id":          "uuid"
}
```

`hashes_verified` is `true` only when `expected` was supplied and every supplied
field matched; without `expected` it is `false` and `hashes_compared` is `[]`.

**Error response (400):**

```json
{
  "ok": false,
  "error": {
    "code":       "VALIDATION_ERROR",
    "message":    "C2PA manifest parse failed: invalid_value (field: harpocrates_binding.tier)",
    "request_id": "uuid"
  }
}
```

A submitted hash that disagrees with the embedded binding is rejected the same
way, naming only the field:

```json
{
  "ok": false,
  "error": {
    "code":       "VALIDATION_ERROR",
    "message":    "submitted hashes do not match the embedded C2PA binding: video_hash",
    "field":      "video_hash",
    "request_id": "uuid"
  }
}
```

Error messages include only the reason code and optional field name. No
manifest content, digest bytes, submitted hash, or proof material appear in
error responses.

---

## Frontend API

```ts
import {
  exportC2paManifest,
  exportC2paManifestFromProof,
  parseC2paManifest,
  verifyRoundTrip,
  C2paParseError,
  C2PA_HARPOCRATES_MAPPING_VERSION,
} from './c2pa'

// Export from raw fields
const exported = exportC2paManifest({
  videoHash, metadataHash, proofId, tier, network, contractId,
})

// Export from an existing ProofManifest
const exported = exportC2paManifestFromProof(proofManifest)

// Import / parse
try {
  const parsed = parseC2paManifest(rawJsonString)
  // parsed.binding.videoHash, .tier, etc.
  // parsed.trustStatus === 'signature_not_checked'
  // parsed.unknownAssertions — safe to display; never act on
} catch (e) {
  if (e instanceof C2paParseError) {
    const { reason, field } = e.toPayload() // only these two fields
  }
}

// Round-trip check
const ok = verifyRoundTrip(exported)
```

---

## Compatibility matrix

| Harpocrates version | C2PA spec target | Mapping version | SHA-256 only |
|---|---|---|---|
| current | 1.3 | 1 | yes |

Only SHA-256 is supported as a hash algorithm. Manifests that declare any
other algorithm (`md5`, `sha512`, etc.) are rejected with `unsupported_algorithm`.

---

## Parser limits

| Limit | Value |
|---|---|
| Maximum manifest size | 256 KiB |
| Maximum assertion count | 64 |
| Maximum assertion label length | 256 chars |
| Maximum assertion data size | 32 KiB |
| Maximum JSON nesting depth | 16 |

These limits are applied in order before any semantic validation, so malformed
or adversarial manifests are rejected early without deep parsing.

---

## Unknown assertions

Assertions whose label is not `harpocrates.binding/v1` are preserved in the
`unknown_assertions` (backend) / `unknownAssertions` (frontend) list with an
explicit `unsupported_semantics: true` flag. They do not affect the parsed
binding and should not be acted upon by callers.

This allows consuming existing C2PA manifests that carry standard C2PA
assertions (e.g., `c2pa.actions`, `c2pa.thumbnail`) without rejecting them.

---

## Rollback

The C2PA feature is additive. No existing endpoints, database schema, contract
storage, Noir circuit, or proof format is modified.

To roll back the hash verification added alongside it:

1. Drop the `expected` block from `/api/c2pa/import` requests; imports without it
   behave exactly as before (the endpoint answers 200 and reports
   `hashes_verified: false`).
2. To revert the code, restore the previous `_parse_binding`/`parse_c2pa_manifest`
   in `backend/c2pa.py` and the previous `/api/c2pa/import` handler in
   `backend/app.py`. Nothing persisted depends on the new fields.
3. `corroborate_binding` and `C2paHashCorroboration` are pure additions; removing
   them breaks no stored evidence.
4. Backfilling is unnecessary: the check reads the manifest at import time and
   writes nothing.

To roll back the whole feature:

1. Remove or disable the `POST /api/c2pa/export` and `POST /api/c2pa/import`
   routes from `backend/app.py`.
2. Remove or stop importing `frontend/src/c2pa.ts`.
3. No database migration or state repair is required.
4. No on-chain state is affected.

Existing proof events, on-chain records, and ZK artifacts are unchanged.

### Threat model notes

| Threat | Mitigation |
|---|---|
| A manifest exported for one video is replayed as evidence of another | Embedded-copy consistency plus the opt-in `expected` corroboration |
| A crafted manifest carries different hashes in the assertion and the top-level object, so consumers disagree | `embedded_binding_mismatch` — the import is rejected |
| A rejection response leaks media hashes into logs or clients | Reason code and field *name* only, in both the response and the log line |
| A matching `expected` block is mistaken for a proof | `trust_status` stays `signature_not_checked`; the response `note` and this document state the limit |

---

## Running the tests

```bash
# Backend — codec, embedded-copy consistency, and corroboration units
cd backend && python -m pytest test_c2pa.py -v

# Backend — endpoint-level hash verification on /api/c2pa/export|import
cd backend && python -m pytest test_c2pa_hashes_api.py -v

# Frontend
cd frontend && npx vitest run src/c2pa.test.ts
```

The backend suites cover valid fixtures, adversarial/malformed inputs,
round-trip preservation, embedded-copy contradictions, submitted-vs-embedded
mismatches, trust status isolation, compatibility matrix assertions, bounded
fuzzing, and privacy (no hash values in error payloads or results).
