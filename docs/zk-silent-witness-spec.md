# Silent Witness — Formal Statement Specification

## Status

This document describes the `silent_witness` circuit as it exists on `main`
at commit `485aaac`. **It documents a known discrepancy between the circuit's
declared interface and its enforced constraints — see [§6 Known Issue](#6-known-issue-unenforced-scope-and-epoch-parameters) — that must be resolved before this
spec can be treated as final.**

## 1. Summary

`silent_witness` lets a prover register evidence (a video hash) against a
credential identity without revealing the credential secret. The circuit
proves knowledge of a `credential_secret` that derives a public
`credential_root`, and binds a `nullifier` to that secret, a separate
`nullifier_secret`, and a canonical digest of the evidence.

## 2. Public / Private Inputs

Circuit signature (`zk/noir/silent_witness/src/main.nr`):

| Input | Visibility | Type |
| --- | --- | --- |
| `credential_secret` | private | `Field` |
| `nullifier_secret` | private | `Field` |
| `video_hash_hi` | public | `Field` |
| `video_hash_lo` | public | `Field` |
| `credential_root` | public | `Field` |
| `nullifier` | public | `Field` |
| `verifier_scope` | public | `Field` |
| `epoch` | public | `Field` |
| `domain_tag` | public | `Field` |
| `circuit_version` | public | `Field` |

On-chain wire order (`docs/zk-conformance-vectors.md`). Two silent-witness
frames are in play. `silent_witness/v1` (`hpx-vi/1`, 160 bytes / 5 fields):

[ 0.. 32) video_hash_hi
[ 32.. 64) video_hash_lo
[ 64.. 96) credential_root
[ 96..128) nullifier
[128..160) domain_tag

`silent_witness/v2` (`hpx-vi/2`, 256 bytes / 8 fields) is the frame this circuit
signature produces, with the circuit version committed as its trailing field:

[  0.. 32) video_hash_hi
[ 32.. 64) video_hash_lo
[ 64.. 96) credential_root
[ 96..128) nullifier
[128..160) verifier_scope
[160..192) epoch
[192..224) domain_tag
[224..256) circuit_version

Note: the registry used to *parse* the 224-byte scoped frame on the registration
path, but no codec described it, and its circuit version was *inferred from the
byte length*. `silent_witness/v2` closes that gap: every public circuit input is
encoded, and the proof names the circuit that produced it. The registration path
no longer accepts that bare frame either — it is rejected with
`RegistryError::CircuitVersionMismatch` (87) — so a 256-byte envelope is the only
scoped frame a verifier will act on. The published four-field browser frame
(`browser_v1` in `zk/noir/circuit_input_schema_v1.json`) is unchanged — it is a
separate, older artifact, and the versioned envelope never replaces a frame
already recorded on chain.

## 3. Statement (as currently enforced)

The circuit enforces exactly two constraints:
evidence_digest = pedersen_hash([DIGEST_ALGORITHM_SHA256, video_hash_hi, video_hash_lo])
derived_root = pedersen_hash([credential_secret])
derived_nullifier = pedersen_hash([credential_secret, nullifier_secret, evidence_digest])

assert derived_root == credential_root
assert derived_nullifier == nullifier

In plain terms, a valid proof attests:

> "I know a `credential_secret` whose Pedersen hash is the public
> `credential_root`, and I know a `nullifier_secret` such that hashing
> `(credential_secret, nullifier_secret, evidence_digest)` gives the public
> `nullifier` — where `evidence_digest` commits to a specific hash algorithm
> ID and a specific 256-bit video hash."

`DIGEST_ALGORITHM_SHA256 = 0` is the only algorithm ID currently defined;
binding it into `evidence_digest` prevents algorithm-substitution and
digest-swap attacks on the evidence commitment (added in commit `04a55a9`).

## 4. Threat Model

**Assumed honest:** the Noir/Barretenberg toolchain, the UltraHonk proving
system's soundness and zero-knowledge properties, and the Soroban verifier
contract's correct evaluation of `verify_proof`.

**Adversary capabilities:** the adversary controls all public inputs and the
proof bytes submitted to `register_anonymous_verified`. It does not know any
prover's `credential_secret` or `nullifier_secret` unless it generated them.

**Guaranteed by the circuit today:**
- An adversary cannot produce a valid proof for a `credential_root` without
  knowing its preimage (binding property of Pedersen hash + circuit
  assertion).
- An adversary cannot produce a valid `nullifier` for evidence it did not
  commit to at proving time — the nullifier is bound to the evidence digest,
  which is bound to the specific video hash and algorithm ID (§3, and the
  `test_swapped_algorithm_id_and_video_hash_hi` / `test_wrong_algorithm_id_in_nullifier`
  cases in `main.nr`).
- Swapping `credential_root` and `nullifier` in the public-input frame is
  rejected (`test_swapped_credential_root_and_nullifier`), as is swapping the
  two video-hash halves (`test_swapped_video_hash_halves`).
- A frame cannot claim a circuit other than the one that produced it: the
  circuit asserts its own `circuit_version` in-circuit (`test_circuit_version_downgrade`)
  and every verifier layer re-checks the committed trailer, so an attacker cannot
  relabel a proof from an older, weaker circuit by editing a length or a field
  (#368).

**Not guaranteed by the circuit today (see §6):**
- Nothing prevents a single valid proof from being accepted under any
  `verifier_scope` or `epoch` value, since neither is folded into any
  constraint.

## 5. Privacy Boundary

**Stays hidden:** `credential_secret`, `nullifier_secret`. Neither appears in
any public input, and per the conformance-vectors doc, rejection paths never
echo witness material — only a stable `{codec, reject_code, field?}` triple.

**Revealed to a verifier:** the video hash (`video_hash_hi/lo`), the
`credential_root` (a one-way commitment to the credential secret, not the
secret itself), and the `nullifier` (a one-way, evidence-bound value used to
prevent double-registration of the same evidence under the same identity).

**Correlation risk:** because `credential_root` is a straight
`pedersen_hash([credential_secret])` with no per-registration randomness, the
same credential produces the same `credential_root` across every proof it
generates. Two registrations from the same credential are linkable via a
shared `credential_root`, even though the underlying secret stays hidden.
This is an inherent property of the current construction, not a bug — but it
should be stated explicitly since it affects what a verifier can infer.

## 6. Known Issue: Unenforced `scope` and `epoch` Parameters

`verifier_scope` and `epoch` are declared as public circuit inputs but **are
not referenced anywhere in the constraint body** of `main()` on current
`main` (commit `485aaac`).

**History:** commit `7b02d75` introduced scope/epoch binding by folding both
into the nullifier via a `scope_hash = pedersen_hash([SCOPED_NULLIFIER_V1,
verifier_scope, epoch])`. Commit `04a55a9`, built from the same earlier
parent, independently introduced evidence-digest binding with a 6-parameter
`main()` that predates scope/epoch entirely. The merge of both branches
(`485aaac`) kept the 8-parameter signature from `7b02d75` but the constraint
body from `04a55a9` — so `verifier_scope` and `epoch` are accepted as inputs
but never hashed, never asserted, and never actually bind the proof to a
scope or epoch.

The test file was merged the same way: `compute_scoped_nullifier` and several
tests named `test_nullifier_from_different_scope`,
`test_nullifier_from_different_epoch`, `test_tampered_scope_public_input`,
and `test_tampered_epoch_public_input` still exist and pass — but only
because they compute their own nullifier with the same (now circuit-inert)
scope hash, not because `main()` enforces the property under test. These
tests currently validate nothing about scope/epoch binding.

**Practical implication:** if any caller of this circuit (contract or
off-chain) relies on `verifier_scope` or `epoch` to prevent a single proof
from being replayed across different verifiers or time windows, that
assumption does not hold today. A proof valid for `scope=0, epoch=0` is
equally valid if submitted with `scope=999, epoch=42`, since the circuit
never checks the relationship.

**This spec deliberately does not describe scope/epoch as an enforced
security property**, unlike the README and test names, which currently imply
otherwise. This should be corrected in code (re-fold `scope_hash` into the
nullifier derivation, consistent with `7b02d75`'s original design) before any
system component depends on scope- or epoch-scoped nullifier uniqueness.

## 7. Versioning

The proof envelope commits the circuit version directly (#368): `main.nr`
declares `CURRENT_CIRCUIT_VERSION` and asserts the public `circuit_version`
input against it, and `silent_witness/v2` (`hpx-vi/2`) carries that field as the
trailing element of the frame. The registry requires the committed value to
equal `EXPECTED_CIRCUIT_VERSION`, so a proof names the circuit that produced it
instead of leaving the verifier to infer it from the frame's byte length. Bumping
the circuit means moving `CURRENT_CIRCUIT_VERSION`, `EXPECTED_CIRCUIT_VERSION`
(Rust / Python / TypeScript), the corpus constant, and
`MIN/MAX_SUPPORTED_CIRCUIT_VERSION` in lockstep; `test_circuit_version_downgrade`
in `main.nr` and the `sw2-neg-02x` / `sw2-neg-07x` corpus cases are the gates that
fail when they drift apart.

The evidence digest is bound to `DIGEST_ALGORITHM_SHA256 = 0`. Introducing a
new evidence hash algorithm requires a new algorithm ID constant and, per the
migration pattern established in `docs/zk-conformance-vectors.md` for the
`hpx-vi` codec, should ship as a new codec/schema version rather than
mutating the existing one in place.

Resolving §6 (re-adding scope/epoch binding) will change the nullifier
derivation and therefore constitutes a breaking change to any already-issued
proof's expected recomputation — it should be versioned explicitly (e.g. a
new `SCOPED_NULLIFIER_V2` domain separator) rather than silently changed, so
that old and new derivations remain distinguishable.

## 8. Reference Vectors

Cross-layer conformance corpus: [`zk/vectors/verifier_conformance_v1.json`](../zk/vectors/verifier_conformance_v1.json)
and [`zk/vectors/verifier_conformance_v2.json`](../zk/vectors/verifier_conformance_v2.json)
(circuit-versioned `silent_witness/v2` frames, #368), described in
[`docs/zk-conformance-vectors.md`](./zk-conformance-vectors.md).
Note the corpus covers the `silent_witness/v1` frame (video hash halves,
credential root, nullifier, domain tag) and the `silent_witness/v2` frame,
which additionally carries `verifier_scope`, `epoch` and the committed
`circuit_version`. The v2 corpus is the versioned, self-describing frame: a
frame that names no circuit cannot be classified as `silent_witness/v2`, so the
bare 224-byte scoped frame is rejected there with `length`, and the registration
path rejects the same frame with `CircuitVersionMismatch` (87). It is no longer a
layout any boundary accepts.
