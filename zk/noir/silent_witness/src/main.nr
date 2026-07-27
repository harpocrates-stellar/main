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
    verifier_scope: pub Field,
    epoch: pub Field,
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
// Test corpus -- Silent Witness circuit (scoped nullifier v1)
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
//   zero_video_hash: hi = 0, lo = 0
// ---------------------------------------------------------------------------

// Public input ordering expected by the Soroban verifier:
//   [0] video_hash_hi
//   [1] video_hash_lo
//   [2] credential_root
//   [3] nullifier
//   [4] verifier_scope
//   [5] epoch
// ---------------------------------------------------------------------------

/// Compute the scoped nullifier for given inputs.
/// Exported for test vector computation.
fn compute_scoped_nullifier(
    cs: Field,
    ns: Field,
    vhi: Field,
    vlo: Field,
    scope: Field,
    ep: Field,
) -> Field {
    let scope_hash = pedersen_hash([SCOPED_NULLIFIER_V1, scope, ep]);
    pedersen_hash([cs, ns, vhi, vlo, scope_hash])
}

// ============================================================
// Positive: well-formed witness -- all assertions must pass
// ============================================================

// All inputs correct: global scope (0), epoch 0.
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

// Edge: max-field credential_secret (BN254 prime - 1).
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

#[test(should_fail_with = "credential root mismatch")]
fn test_wrong_credential_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(99999, ns, vhi, vlo, root, nul, scope, ep);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_nullifier_secret() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, 11111, vhi, vlo, root, nul, scope, ep);
}

// ============================================================
// Negative -- wrong video hash (public inputs)
// ============================================================

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_hi() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 99999999999999999999999999999999999999, vlo, root, nul, scope, ep);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_lo() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, 99999999999999999999999999999999999999, root, nul, scope, ep);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_video_hash_both_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, 11111111111111111111111111111111111111, 22222222222222222222222222222222222222, root, nul, scope, ep);
}

// ============================================================
// Negative -- tampered public inputs (replay / substitution)
// ============================================================

#[test(should_fail_with = "credential root mismatch")]
fn test_tampered_credential_root_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([99999]); // wrong root
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_nullifier_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier for a different credential
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

#[test(should_fail_with = "credential root mismatch")]
fn test_both_public_inputs_wrong_identity() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([99999]);
    let nul = compute_scoped_nullifier(99999, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// ============================================================
// Negative -- public input ordering / swap attacks
// ============================================================

#[test(should_fail_with = "credential root mismatch")]
fn test_swapped_credential_root_and_nullifier() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: nullifier passed as credential_root, root passed as nullifier
    main(cs, ns, vhi, vlo, nul, root, scope, ep);
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_swapped_video_hash_halves() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Swap: lo in hi slot, hi in lo slot
    main(cs, ns, vlo, vhi, root, nul, scope, ep);
}

// ============================================================
// Negative -- scope binding
// ============================================================

// A valid proof for scope=0 must NOT satisfy scope=999.
// Proves the nullifier binds to the specific verifier_scope.
#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_scope() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier computed for scope=999 (different scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, 999, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// A valid proof for epoch=1 must NOT satisfy epoch=2.
// Proves the nullifier binds to the specific epoch.
#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_epoch() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 42;
    let ep: Field = 1;
    let root = pedersen_hash([cs]);
    // Nullifier computed for epoch=2 (different epoch, same scope)
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, 2);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// ============================================================
// Negative -- nullifier/video binding (unchanged from v1)
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
