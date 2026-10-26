use harpocrates_common::{
    DIGEST_ALGORITHM_SHA256,
    DOMAIN_NETWORK_FIELD,
    DOMAIN_PROTOCOL_FIELD,
    DOMAIN_VERSION_FIELD,
    SCOPED_NULLIFIER_V1,
};

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: Field,
    video_hash_lo: Field,
    verifier_scope: Field,
    epoch: Field,
) -> pub (Field, Field, Field) {
    let scope_hash = std::hash::pedersen_hash([
        SCOPED_NULLIFIER_V1,
        verifier_scope,
        epoch,
    ]);

    // Commit to the complete canonical evidence digest with algorithm binding.
    // This must match the derivation in the main silent_witness circuit so that
    // the off-chain helper produces the same credential_root and nullifier that
    // the main circuit expects.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
        scope_hash,
    ]);

    let credential_root = std::hash::pedersen_hash([credential_secret]);
    let nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);
    let domain_tag = std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);

    (credential_root, nullifier, domain_tag)
}

// =============================================================================
// Test helpers: compute Merkle tree nodes and domain separator for the
// revocation witness non-membership circuit.
//
// Run `nargo test --show-output` to extract field values for Prover.toml
// and shared conformance vectors.
// =============================================================================

/// Compute the test domain separator.
/// Must match the value in the Soroban contract test vectors.
fn test_domain_separator() -> Field {
    // pedersen(["HARPOCRATES_REVOCATION_V1", 0, 0])
    std::hash::pedersen_hash([0x484152504f4352415445535f5245564f434154494f4e5f5631, 0, 0])
}

/// Compute the Merkle root for 8 leaves (depth 3, Pedersen).
fn compute_merkle_root(
    l0: Field, l1: Field, l2: Field, l3: Field,
    l4: Field, l5: Field, l6: Field, l7: Field,
) -> Field {
    let n01 = std::hash::pedersen_hash([l0, l1]);
    let n23 = std::hash::pedersen_hash([l2, l3]);
    let n45 = std::hash::pedersen_hash([l4, l5]);
    let n67 = std::hash::pedersen_hash([l6, l7]);
    let n0123 = std::hash::pedersen_hash([n01, n23]);
    let n4567 = std::hash::pedersen_hash([n45, n67]);
    std::hash::pedersen_hash([n0123, n4567])
}

/// Compute all parameters for the base test fixture and print them.
/// Credential: cs=12345, ns=67890
/// Revoked leaves: 0, root(33333), root(44444), ..., root(99999)
#[test]
fn test_compute_revocation_tree_params() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let (credential_root, nullifier, domain_tag) = main(cs, ns, 0, 0, 0, 0);

    let l0: Field = 0;
    let l1 = std::hash::pedersen_hash([33333]);
    let l2 = std::hash::pedersen_hash([44444]);
    let l3 = std::hash::pedersen_hash([55555]);
    let l4 = std::hash::pedersen_hash([66666]);
    let l5 = std::hash::pedersen_hash([77777]);
    let l6 = std::hash::pedersen_hash([88888]);
    let l7 = std::hash::pedersen_hash([99999]);

    let tree_root = compute_merkle_root(l0, l1, l2, l3, l4, l5, l6, l7);
    let ds = test_domain_separator();

    // Verify all computed values are non-zero (proof of work).
    assert(credential_root != 0);
    assert(nullifier != 0);
    assert(domain_tag != 0);
    assert(tree_root != 0);
    assert(ds != 0);
    assert(l1 != 0);
    assert(l7 != 0);

    // Bind the values so the compiler doesn't optimize them away.
    let _ = (credential_root, nullifier, domain_tag, tree_root, ds, l0, l1, l2, l3, l4, l5, l6, l7);
}

// =============================================================================
// Helper circuit tests
//
// These tests assert that silent_witness_helper derives public inputs matching
// committed vectors from zk/noir/silent_witness/Prover.toml.example and
// zk/vectors/verifier_conformance_v2.json, including zero and max-field edge cases.
// =============================================================================

global EXPECTED_DOMAIN_TAG: Field = 0x4aa038f0a27b6675d7122ae2d4e197c21e83fbe30143a5c83ff35c9514b92c55;
global MAX_FIELD: Field = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000;

fn compute_expected_nullifier(
    cs: Field,
    ns: Field,
    vhi: Field,
    vlo: Field,
    scope: Field,
    epoch: Field,
) -> Field {
    let scope_hash = std::hash::pedersen_hash([
        SCOPED_NULLIFIER_V1,
        scope,
        epoch,
    ]);
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        vhi,
        vlo,
        scope_hash,
    ]);
    std::hash::pedersen_hash([
        cs,
        ns,
        evidence_digest,
    ])
}

/// Test matching zk/noir/silent_witness/Prover.toml.example inputs:
/// cs = 12345, ns = 67890, vhi = 1, vlo = 2, scope = 0, epoch = 0.
#[test]
fn test_prover_toml_example_derivation() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 1;
    let vlo: Field = 2;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    let expected_root = std::hash::pedersen_hash([cs]);
    assert(credential_root == expected_root);
    assert(credential_root == 0x1a65fb219ffd58992a8c16d3038ef77e4696a8e43e1fb2debdb03b5d9b0ee8a9);

    let expected_null = compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch);
    assert(nullifier == expected_null);

    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Test canonical inputs from case sw2-pos-001-canonical in zk/vectors/verifier_conformance_v2.json.
#[test]
fn test_conformance_v2_canonical() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0x000102030405060708090a0b0c0d0e0f;
    let vlo: Field = 0x101112131415161718191a1b1c1d1e1f;
    let scope: Field = 0x0404040404040404040404040404040404040404040404040404040404040404;
    let epoch: Field = 5;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    assert(credential_root == std::hash::pedersen_hash([cs]));
    assert(nullifier == compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch));
    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Mirroring the main circuit's test_zero_credential_secret: zero credential_secret is a valid field element.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    assert(credential_root == std::hash::pedersen_hash([0]));
    assert(nullifier == compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch));
    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Mirroring the main circuit's test_max_field_credential_secret and sw2-pos-004-max-canonical-field:
/// Max canonical field element (BN254 scalar field modulus - 1).
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = MAX_FIELD;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    assert(credential_root == std::hash::pedersen_hash([MAX_FIELD]));
    assert(nullifier == compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch));
    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Mirroring the main circuit's test_zero_video_hash and sw2-pos-003-zero-video-hash:
/// Blank-frame video hash (both hi and lo limbs are zero).
#[test]
fn test_zero_video_hash() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0;
    let vlo: Field = 0;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    assert(credential_root == std::hash::pedersen_hash([cs]));
    assert(nullifier == compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch));
    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Mirroring sw2-pos-005-zero-epoch and sw2-pos-006-zero-scope:
/// Explicit zero verifier scope and zero epoch with conformance vector video hash.
#[test]
fn test_zero_scope_and_epoch() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0x000102030405060708090a0b0c0d0e0f;
    let vlo: Field = 0x101112131415161718191a1b1c1d1e1f;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (credential_root, nullifier, domain_tag) = main(cs, ns, vhi, vlo, scope, epoch);

    assert(credential_root == std::hash::pedersen_hash([cs]));
    assert(nullifier == compute_expected_nullifier(cs, ns, vhi, vlo, scope, epoch));
    assert(domain_tag == EXPECTED_DOMAIN_TAG);
}

/// Mirroring the main circuit's test_nullifier_secret_field_edges_are_distinct:
/// Max field nullifier secret vs zero nullifier secret produces distinct nullifiers.
#[test]
fn test_max_field_nullifier_secret_distinct() {
    let cs: Field = 12345;
    let vhi: Field = 1;
    let vlo: Field = 2;
    let scope: Field = 0;
    let epoch: Field = 0;

    let (_, nullifier_max, _) = main(cs, MAX_FIELD, vhi, vlo, scope, epoch);
    let (_, nullifier_zero, _) = main(cs, 0, vhi, vlo, scope, epoch);

    assert(nullifier_max != nullifier_zero);
}
