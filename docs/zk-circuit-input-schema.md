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
hash halves are passed to the published browser helper and main circuits.
Scope and epoch are accepted by the input envelope, but nonzero values are
rejected before execution when the loaded artifact cannot bind them. They are
passed to a scoped circuit only when that circuit's ABI is present.

The checked-in browser artifacts produce a four-field frame
(`video_hash_hi`, `video_hash_lo`, `credential_root`, `nullifier`) and a helper
with two return fields. The schema records that as `browser_v1` and pins the
SHA-256 digests of both bytecode strings. The browser validates the ABI,
compiler version, digests, proof bounds, and four public values before returning
a proof. No domain tag is invented for this artifact.

The verifier separately recognizes a five-field unscoped `silent_witness/v1`
frame (`video_hash_hi`, `video_hash_lo`, `credential_root`, `nullifier`,
`domain_tag`) and a seven-field scoped `silent_witness/v2` frame with
`verifier_scope` and `epoch` before `domain_tag`. The browser retains the
five-field and seven-field ABI paths for matching future artifacts, including
domain-tag and scope/epoch forwarding. It checks the returned field count,
order, and values against the input and helper result. A scoped request cannot
produce a four- or five-field proof. The aggregated proof path remains available.

## Artifact compatibility and migration

The current Noir source declares seven public fields and a three-field helper
return. The five-field verifier frame has **no matching checked-in browser
artifact**. The published four-field proof can be generated and checked against
its own artifact, but it must not be relabelled as a five-field verifier proof.
The existing backend and contract verifier require their own five- or
seven-field frames, so registration of a four-field browser proof still needs
a coordinated artifact/verifier migration.

Publishing a verifier-compatible browser artifact requires a separate pinned
build and verifier compatibility check for the five-field and/or seven-field
statement. The current source fails the pinned Nargo `1.0.0-beta.9` compile
check, so that migration must resolve the source build first. Stored
proofs are not rewritten. Rollback is the previous browser bundle; this change
does not modify on-chain storage or the verifier codec.
