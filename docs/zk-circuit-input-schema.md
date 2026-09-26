# Silent Witness input schema

`silent_witness/input-v1` versions the browser proving **input envelope**. Its
machine-readable definition is in
[`zk/noir/circuit_input_schema_v1.json`](../zk/noir/circuit_input_schema_v1.json),
with synthetic conformance cases in
[`zk/vectors/circuit_input_schema_v1.json`](../zk/vectors/circuit_input_schema_v1.json).
It does not change the proof manifest version, verifier codec, or on-chain
statement.

The envelope accepts a 32-byte video hash, two canonical BN254 secret fields,
an optional canonical verifier scope, and an optional nonnegative safe-integer
epoch. Decimal and hexadecimal field strings are normalized to decimal before
calling Noir. Omitting `inputSchemaVersion` selects version 1 for existing callers.
Unknown versions, malformed hashes, and noncanonical fields fail with fixed
error codes that contain no input or witness values. The high and low 128-bit
hash halves, scope, and epoch are passed to the existing helper and main
circuit paths; scope and epoch are never silently dropped.

The verifier already recognizes a five-field unscoped `silent_witness/v1`
frame (`video_hash_hi`, `video_hash_lo`, `credential_root`, `nullifier`,
`domain_tag`) and a seven-field scoped `silent_witness/v2` frame with
`verifier_scope` and `epoch` before `domain_tag`. The browser checks the
returned field count, order, and values against the input and helper result.
A scoped request cannot produce a five-field proof. The existing domain tag
and aggregated proof paths remain available.

## Artifact compatibility and migration

The checked-in browser `silent_witness` artifact still exposes four public
fields and its helper returns two fields. The current Noir source declares
seven public fields and a three-field helper return. The five-field verifier
frame therefore has **no matching checked-in browser artifact**. This input
schema does not relabel the old artifact or claim its proof is accepted by the
current verifier. Proof generation fails closed if the loaded artifact cannot
produce the expected helper result and public frame.

Publishing a working browser prover requires a separate pinned artifact build
and verifier compatibility check for the five-field and/or seven-field
statement. The current source fails the pinned Nargo `1.0.0-beta.9` compile
check, so the artifact migration must resolve that source build first. Stored
proofs are not rewritten. Rollback is the previous browser bundle; this change
does not modify on-chain storage or the verifier codec.
