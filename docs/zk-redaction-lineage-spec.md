# Redaction Lineage Witness -- Formal Statement Specification

## 1. Summary

`redaction_lineage` proves that a committed derivative was made from a
previously registered evidence commitment using one permitted lineage operation,
without revealing source chunks, removed regions, transformation settings, or
blinding factors.  It is a bounded prototype: `MAX_CHUNKS = 4`, matching the
lineage graph fan-out limit, and it does not enable contract verification.

The source is bound by the parent's registered `silent_witness` commitment;
the circuit deliberately does **not** derive or expose `credential_root`.
Chunks are committed in order with a Pedersen accumulator, so substituting or
reordering a source chunk changes the parent commitment.  The derivative
commitment binds that parent accumulator, the ordered visible chunks, the
private transformation-parameter digest, the operation, and a fresh blinding
factor.

## 2. Public / Private Inputs

| Input | Visibility | Type |
| --- | --- | --- |
| `parent_commitment` | public | Field; existing registered-evidence/silent-witness binding |
| `output_commitment` | public | Field; commitment to the derivative |
| `operation_type` | public | Field; 1 crop, 2 transcode, 3 blur, 4 redact, 5 compose |
| `replay_binding` | public | Field; application claim/manifest binding |
| `domain_tag` | public | Field; `redaction_witness/v1` domain tag |
| `parent_chunks`, `visible_chunks` | private | `[Field; MAX_CHUNKS]` ordered media commitments |
| `removed_descriptors` | private | `[Field; MAX_CHUNKS]`; zero means visible |
| `parameters_digest`, `blinding_factor` | private | Field |

The hpx-vi/1 frame is five 32-byte canonical fields in the exact order above.
It contains no pixels, chunks, region coordinates, parameters, or secrets.

## 3. Statement as enforced

The circuit asserts all of the following:

1. The operation is in the fixed allow-list `crop`, `transcode`, `blur`,
   `redact`, or `compose`.
2. `parent_commitment` equals the ordered Pedersen accumulator of the supplied
   parent chunks. Thus a wrong crop source or reordered chunks cannot satisfy
   the proof.
3. Each output slot with a zero removed-descriptor is constrained to equal the
   corresponding parent slot. A non-zero removed-descriptor marks a private
   slot for which the prototype does not expose a source chunk. The current
   circuit is a commitment-level redaction model; it does not yet encode
   operation-specific pixel, crop, blur, or transcode semantics.
4. `output_commitment` is a domain-separated Pedersen commitment to the parent
   commitment, operation, parameters digest, ordered visible chunks, replay
   binding, and blinding factor. A proof cannot be replayed for another claim.
5. `domain_tag` is the fixed `redaction_witness/v1` tag, preventing use as a
   silent-witness or revocation-witness proof.

## 4. Known issues

- This prototype proves commitment-level transformation lineage, not pixel-level
  rendering correctness. Production support needs a media canonicalisation and
  per-operation semantics standard before it can attest a particular encoder
  implementation.
- The unresolved questions are explicitly deferred: canonical media decoder,
  multi-parent compose semantics, and calibrated feasibility measurements.
- Live Soroban verification is intentionally out of scope; see
  `contracts/VERIFIER_INTEGRATION.md`.
