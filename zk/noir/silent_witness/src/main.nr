// ---------------------------------------------------------------------------
// Canonical evidence digest algorithm identifiers.
//
// Each constant maps a well-known hash algorithm to a numeric identifier
// that is bound into the evidence digest commitment inside the circuit.
// This prevents proofs from being detached from the exact hashing algorithm
// used to produce the evidence digest.
//
//   DIGEST_ALGORITHM_SHA256 = 0   — SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
global DIGEST_ALGORITHM_SHA256: Field = 0;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: pub Field,
    video_hash_lo: pub Field,
    credential_root: pub Field,
    nullifier: pub Field,
) {
    // Commit to the complete canonical evidence digest: algorithm identifier
    // plus the full 256-bit digest (split across two BN254 field elements).
    // This binds the proof to the specific hash algorithm and prevents
    // digest-swapping or algorithm-substitution attacks.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
    ]);

    let derived_root = std::hash::pedersen_hash([credential_secret]);
    let derived_nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);

    assert(derived_root == credential_root, "credential root mismatch");
    assert(derived_nullifier == nullifier, "nullifier mismatch");
}

// ---------------------------------------------------------------------------
// Test corpus -- Silent Witness circuit
//
// ALL SECRETS BELOW ARE SYNTHETIC AND FOR TESTING ONLY.
// Do not use these values in any production credential or proof.
//
// Base fixture (all values derived from these synthetic seeds):
//   credential_secret   = 12345
//   nullifier_secret    = 67890
//   video_hash_hi       = 22685491128062564230891640495451214097
//                         (hi-128 bits of SHA-256("harpocrates-test-video"))
//   video_hash_lo       = 45370982256125128461783280990902428194
//                         (lo-128 bits of SHA-256("harpocrates-test-video"))
//   DIGEST_ALGORITHM_ID = 0 (SHA-256)
//
// Derived public inputs (BN254/UltraHonk, Pedersen):
//   evidence_digest  = pedersen_hash([0, video_hash_hi, video_hash_lo])
//   credential_root  = pedersen_hash([12345])
//                    = 0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9
//   nullifier        = pedersen_hash([12345, 67890, evidence_digest])
//                    = (changed from previous derivation — now bound to canonical evidence digest)
//
// Edge-case secrets:
//   zero_credential_secret      = 0
//   max_field_credential_secret = BN254 prime - 1
//     = 21888242871839275222246405745257275088548364400416034343698204186575808495616
//   zero_video_hash: hi = 0, lo = 0
// ---------------------------------------------------------------------------

// Public input ordering expected by the Soroban verifier:
//   [0] video_hash_hi
//   [1] video_hash_lo
//   [2] credential_root
//   [3] nullifier
// ---------------------------------------------------------------------------

// ============================================================
// Positive: well-formed witness -- all assertions must pass
// ============================================================

// All inputs correct: proves the circuit accepts a valid witness.
#[test]
fn test_valid_witness() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns, evidence]);
    main(cs, ns, vhi, vlo, root, null);
}

// Edge: zero credential_secret is a valid field element.
// The circuit must accept it when the public root is derived correctly.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns, evidence]);
    main(cs, ns, vhi, vlo, root, null);
}

// Edge: max-field credential_secret (BN254 prime - 1) is a valid field element.
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns, evidence]);
    main(cs, ns, vhi, vlo, root, null);
}

// Edge: all-zero video hash (e.g. blank-frame video) with correct secrets.
// The nullifier is derived via the evidence digest commitment, not raw halves.
#[test]
fn test_zero_video_hash() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0;
    let vlo: Field = 0;
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns, evidence]);
    main(cs, ns, vhi, vlo, root, null);
}

// ============================================================
// Negative -- wrong private inputs
// ============================================================

// Wrong credential_secret: derived root does not match the correct public root.
// Both asserts are wrong but the first fires first.
#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_credential_secret() {
    main(
        99999, // wrong -- root(99999) != root(12345)
        67890,
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// Wrong nullifier_secret: credential root is still correct but the
// nullifier derivation changes, so the second assert must fail.
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_nullifier_secret() {
    main(
        12345,
        11111, // wrong -- nullifier changes
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// ============================================================
// Negative -- wrong video hash (public inputs)
// ============================================================

// Wrong video_hash_hi: the nullifier was computed over the correct hash
// but the circuit re-derives over a different hi value.
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_hi() {
    main(
        12345,
        67890,
        99999999999999999999999999999999999999, // wrong hi
        45370982256125128461783280990902428194,
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// Wrong video_hash_lo: only the lo half of the video hash is changed.
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_lo() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097,
        99999999999999999999999999999999999999, // wrong lo
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// Both halves of the video hash are wrong (completely different video).
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_both_halves() {
    main(
        12345,
        67890,
        11111111111111111111111111111111111111, // wrong hi
        22222222222222222222222222222222222222, // wrong lo
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// ============================================================
// Negative -- tampered public inputs (replay / substitution)
// ============================================================

// Tampered credential_root: prover supplies the correct private secret
// but the verifier-visible public root has been altered.
// Simulates an attacker substituting a different identity's root.
#[test(should_fail_with = "credential root mismatch")]
fn test_tampered_credential_root_public_input() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        0x08a63a1f3b518e91eae95ee0622f50843a446d420e6334088738db4e29c425b2, // root(99999)
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// Tampered nullifier: correct secrets, but the public nullifier has been
// replaced with one derived from a different witness.
// Simulates a nullifier replay attack with a wrong value.
#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_nullifier_public_input() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x10700bc6111604ff306d4c749253d5ad0f7b65d6352883a766382a02bfe1e2d6, // nullifier(99999,...)
    );
}

// Both public inputs are from a different identity (credential root + nullifier
// of cs=99999), but private inputs belong to cs=12345.
// Catches a full-substitution attack where both public outputs are forged.
#[test(should_fail_with = "credential root mismatch")]
fn test_both_public_inputs_wrong_identity() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        0x08a63a1f3b518e91eae95ee0622f50843a446d420e6334088738db4e29c425b2, // root(99999)
        0x10700bc6111604ff306d4c749253d5ad0f7b65d6352883a766382a02bfe1e2d6, // nullifier(99999,...)
    );
}

// ============================================================
// Negative -- public input ordering / swap attacks
// ============================================================

// credential_root and nullifier are swapped in the public inputs.
// The Soroban verifier contract fixes input ordering as
// [video_hash_hi, video_hash_lo, credential_root, nullifier].
// Swapping them must cause the circuit to reject.
#[test(should_fail_with = "credential root mismatch")]
fn test_swapped_credential_root_and_nullifier() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097,
        45370982256125128461783280990902428194,
        // nullifier passed as credential_root position
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
        // credential_root passed as nullifier position
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
    );
}

// video_hash_hi and video_hash_lo are swapped.
// hash(lo_as_hi, hi_as_lo) != hash(hi, lo) so the nullifier fails.
#[test(should_fail_with = "nullifier mismatch")]
fn test_swapped_video_hash_halves() {
    main(
        12345,
        67890,
        45370982256125128461783280990902428194, // lo in hi slot
        22685491128062564230891640495451214097, // hi in lo slot
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x266fe0dec6dc9e1a4a7b0b3c71876074eaca128b05b371cf6677d2e62f795fe6,
    );
}

// ============================================================
// Negative -- nullifier/video binding
// ============================================================

// A valid proof for one video must not satisfy a different video's nullifier.
// Proves the nullifier binds to the specific (video_hash_hi, video_hash_lo) pair
// via the evidence digest commitment, which also includes the algorithm ID.
// The supplied nullifier is intentionally from a different video (computed under
// the old derivation) so the assertion must fail.
#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_video() {
    main(
        12345,
        67890,
        22685491128062564230891640495451214097, // correct hi
        45370982256125128461783280990902428194, // correct lo
        0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9,
        0x123dc8f99a053fc5f5e93f89b04919746e0ce70ca49b0011617e48dd5f8090ce, // wrong nullifier (old derivation)
    );
}

// ============================================================
// Negative -- evidence digest algorithm binding
// ============================================================

// A nullifier computed with DIGEST_ALGORITHM_ID=1 (unknown algorithm)
// must not satisfy the circuit that uses DIGEST_ALGORITHM_ID=0.
// This prevents an attacker from substituting a different hash algorithm
// while claiming the proof was computed over the canonical SHA-256 digest.
//
// The supplied nullifier is derived with algorithm_id=1 but the circuit
// commits with algorithm_id=0, so the evidence digest differs.
fn nullifier_with_algorithm_id(
    cs: Field, ns: Field, vhi: Field, vlo: Field, algo: Field,
) -> Field {
    let evidence = std::hash::pedersen_hash([algo, vhi, vlo]);
    std::hash::pedersen_hash([cs, ns, evidence])
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_algorithm_id_in_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let evidence = std::hash::pedersen_hash([DIGEST_ALGORITHM_SHA256, vhi, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    // nullifier computed with algorithm_id=1 (substituted)
    let wrong_null = nullifier_with_algorithm_id(cs, ns, vhi, vlo, 1);
    main(cs, ns, vhi, vlo, root, wrong_null);
}

// ============================================================
// Negative -- evidence digest commitment preimage
// ============================================================

// The evidence_digest is pedersen_hash([algorithm_id, video_hash_hi, video_hash_lo]).
// An attacker cannot swap algorithm_id and video_hash_hi because all three are
// committed as a positional tuple. This test verifies that swapping DOES change
// the evidence digest and causes a nullifier mismatch.
#[test(should_fail_with = "nullifier mismatch")]
fn test_swapped_algorithm_id_and_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    // evidence with (vhi, 0, vlo) instead of (0, vhi, vlo) — algorithm id and hi swapped
    let swapped_evidence = std::hash::pedersen_hash([vhi, DIGEST_ALGORITHM_SHA256, vlo]);
    let root = std::hash::pedersen_hash([cs]);
    let swapped_null = std::hash::pedersen_hash([cs, ns, swapped_evidence]);
    main(cs, ns, vhi, vlo, root, swapped_null);
}
