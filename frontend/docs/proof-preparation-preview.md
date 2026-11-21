# Read-only proof preparation preview

Evidence Studio shows a read-only **proof preparation preview** for the Silent
Witness (zero-knowledge) tier before proving starts. It answers two questions
without touching secrets or the network:

- Which **canonical public inputs** would the proof bind?
- Which **policy version** defines their encoding?

The view model is built by `frontend/src/proofPreparationPreview.ts` and
rendered by `frontend/src/components/ProofPreparationPreview.tsx`. The hook
`useEvidence()` exposes it as `proofPreparation`; `StudioView` renders it once
an evidence package exists and the Silent Witness tier is selected.

## What it shows

| Field | Source | Disclosure |
| :--- | :--- | :--- |
| `video_hash_hi` | High 128 bits of `videoHash` as a canonical BN254 field | Public |
| `video_hash_lo` | Low 128 bits of `videoHash` as a canonical BN254 field | Public |
| `verifier_scope` | Canonical scope element (`0` = global scope) | Public |
| `epoch` | Day-granular epoch (`floor(now / 86400000)`) | Public |

The policy line reports `silent_witness/input-v1` and its version
(`CIRCUIT_INPUT_SCHEMA_VERSION`). Encoding is delegated to the same normalizer
that proving uses (`canonicalSilentWitnessPublicInputs` in
`circuitInputSchema.ts`), so the preview cannot drift from the circuit inputs.

## What it never shows

`credential_secret` and `nullifier_secret` are listed by name with the
`[REDACTED]` placeholder. The preview module does not accept seed material at
all — the values are never passed in, so they cannot be rendered, logged, or
serialized. A `ProofPackage` that already carries `silentWitness` material is
not read by the preview.

## Read-only guarantees

- No circuit artifacts are loaded and no proof is generated.
- No wallet call, no `fetch`, and no Stellar transaction are performed. The
  result carries `readOnly: true` and `transactionSubmission: 'none'`.
- The panel contains no buttons, so nothing can be submitted from the preview.

## Failure and boundary behavior

All failures are fail-closed with fixed codes and messages that contain no
evidence values:

| Code | Meaning |
| :--- | :--- |
| `MISSING_EVIDENCE` | No evidence package exists yet. |
| `UNSUPPORTED_TIER` | The selected tier does not generate a ZK proof. |
| `INVALID_PUBLIC_INPUTS` | The video hash, scope, or epoch is not canonical. |

`INVALID_PUBLIC_INPUTS` covers malformed hashes, non-canonical scopes (for
example a scope name instead of a field element), and negative or non-integer
epochs. Proving uses the same normalizer, so an input that fails the preview
would also fail proof generation.

## Tests

- `frontend/src/proofPreparationPreview.test.ts` — canonical values, policy
  version, determinism, hex normalization, epoch default, concealment of
  witness material, fail-closed boundaries, and the absence of network work.
- `frontend/src/components/ProofPreparationPreview.test.tsx` — rendering of
  the read-only panel, the empty state, the error alert, and no submit action.
- `frontend/src/views/StudioView.test.tsx` — the preview appears before
  proving for the Silent Witness tier and is hidden for other tiers.
