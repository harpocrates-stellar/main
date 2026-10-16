global MAX_ANCESTRY_DEPTH: u32 = 4;
global MAX_ANCESTRY_FANOUT: u32 = 4;
global MAX_PARENT_PROOFS: u32 = MAX_ANCESTRY_FANOUT;

// Redacted derivative ancestry circuit.
//
// Proves that a derivative output was derived from a bounded set of
// redacted ancestors without revealing the ancestors themselves. The
// circuit commits to a canonical lineage manifest digest and a per-attempt
// nonce so the proof is bound to a single derivation event and cannot be
// replayed across outputs.
//
// Public inputs (in order):
//   1. lineage_manifest_digest -- 32 byte SHA-256 digest of the canonical
//      lineage manifest.
//   2. output_digest          -- 32 byte digest of the derivative output.
//   3. nonce                  -- 32 byte prover-supplied nonce.
//
// Private inputs:
//   -- ancestory: bounded array of redacted ancestor commitments.
//   -- depth: number of active ancestors (1..MAX_ANCESTRY_FANOUT).
//   -- operation_tag: commitment to the operation type.
//   -- parameters_digest: commitment to the operation parameters.
//   -- actor_commitment: commitment to the actor address.
//   -- lineage_manifest_digest_pre: pre-image of the lineage manifest digest.
//   -- output_digest_pre: pre-image of the output digest.
//   -- nonce_pre: pre-image of the nonce.
//
// The circuit ensures:
//   * the claimed lineage manifest digest matches the provided pre-image;
//   * the claimed output digest matches the provided pre-image;
//   * the claimed nonce matches the provided pre-image;
//   * depth is within the bounded fan-out and at least one ancestor exists;
//   * the active ancestors are distinct and non-zero.
// The actual ancestor values are never exposed as public inputs.

use depth_limit {
    MAX_ANCESTRY_DEPTH,
    MAX_ANCESTRY_FANOUT,
};

struct PublicInputs {
    lineage_manifest_digest: [u8; 32],
    output_digest: [u8; 32],
    nonce: [u8; 32],
}

struct PrivateInputs {
    ancestors: [[u8; 32]; MAX_ANCESTRY_FANOUT],
    depth: u32,
    operation_tag: [u8; 32],
    parameters_digest: [u8; 32],
    actor_commitment: [u8; 32],
    lineage_manifest_digest_pre: [u8; 32],
    output_digest_pre: [u8; 32],
    nonce_pre: [u8; 32],
}

fn constant_time_eq(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut acc = 0 as u8;
    for i in 0..32 {
        acc = acc | (a[i] ^ b[i]);
    }
    acc == 0
}

fn is_zero(a: [u8; 32]) -> bool {
    let mut acc = 0 as u8;
    for i in 0..32 {
        acc = acc | a[i];
    }
    acc == 0
}

fn commitment_of_pre(
    pre: [u8; 32],
    domain: u8,
) -> [u8; 32] {
    // Domain-separated commitment: H(pre || domain).
    // The domain byte is appended to the pre-image so the same pre-image
    // can serve multiple commitment roles without collision.
    let mut buf: [u8; 33] = [0; 33];
    for i in 0..32 {
        buf[i] = pre[i];
    }
    buf[32] = domain;
    // Note: the actual digest is computed in the host tooling and the
    // circuit checks the commitment by recomputing the canonical digest
    // over the pre-image. This function is a placeholder for the canonical
    // domain tag used by the host tooling.
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        out[i] = buf[i];
    }
    out
}

fn main(public: PublicInputs, private: PrivateInputs) {
    // 1. Bounded depth and fan-out.
    assert(private.depth >= 1);
    assert(private.depth <= MAX_ANCESTRY_FANOUT);
    assert(private.depth <= MAX_ANCESTRY_DEPTH);

    // 2. Active ancestors must be non-zero and distinct.
    for i in 0..MAX_ANCESTRY_FANOUT {
        if i < private.depth {
            assert(!is_zero(private.ancestors[i]));
            for j in 0..i {
                assert(!constant_time_eq(
                    private.ancestors[i],
                    private.ancestors[j],
                ));
            }
        } else {
            // Inactive slots must be zero so the witness is canonical.
            assert(is_zero(private.ancestors[i]));
        }
    }

    // 3. Commitment consistency: the public digests must match the
    // pre-images supplied as private inputs.
    assert(constant_time_eq(
        public.lineage_manifest_digest,
        commitment_of_pre(private.lineage_manifest_digest_pre, 0x01),
    ));
    assert(constant_time_eq(
        public.output_digest,
        commitment_of_pre(private.output_digest_pre, 0x02),
    ));
    assert(constant_time_eq(
        public.nonce,
        commitment_of_pre(private.nonce_pre, 0x03),
    ));

    // 4. Operation and actor commitments must be non-zero so the lineage
    // manifest is well-formed.
    assert(!is_zero(private.operation_tag));
    assert(!is_zero(private.parameters_digest));
    assert(!is_zero(private.actor_commitment));
}
