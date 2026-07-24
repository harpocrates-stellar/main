fn main(
    credential_secret: Field,
    nullifier_secret: Field,
) -> pub (Field, Field) {
    let credential_root = std::hash::pedersen_hash([credential_secret]);
    let nullifier = std::hash::pedersen_hash([credential_secret, nullifier_secret]);
    (credential_root, nullifier)
}

// ---------------------------------------------------------------------------
// Test helpers: compute Merkle tree nodes for revocation witness testing
// ---------------------------------------------------------------------------

/// Compute the revocation Merkle tree root and siblings for leaf index 0
/// (credential_secret = 12345 at leaf position 0).
///
/// Returns (revocation_root, sibling_0, sibling_1, sibling_2, nullifier).
/// Run `nargo test --show-output` to extract the field values for Prover.toml.
#[test]
fn test_compute_revocation_tree_params() {
    // Leaf values (credential roots)
    let l0 = main(12345, 67890).0;
    let l1 = std::hash::pedersen_hash([99999]);
    let l2 = std::hash::pedersen_hash([88888]);
    let l3 = std::hash::pedersen_hash([77777]);
    let l4 = std::hash::pedersen_hash([66666]);
    let l5 = std::hash::pedersen_hash([55555]);
    let l6 = std::hash::pedersen_hash([44444]);
    let l7 = std::hash::pedersen_hash([33333]);

    let n01 = std::hash::pedersen_hash([l0, l1]);
    let n23 = std::hash::pedersen_hash([l2, l3]);
    let n45 = std::hash::pedersen_hash([l4, l5]);
    let n67 = std::hash::pedersen_hash([l6, l7]);

    let n0123 = std::hash::pedersen_hash([n01, n23]);
    let n4567 = std::hash::pedersen_hash([n45, n67]);

    let root = std::hash::pedersen_hash([n0123, n4567]);
    let nullifier = main(12345, 67890).1;

    assert(root != 0);
    assert(l1 != 0);
    assert(n23 != 0);
    assert(n4567 != 0);
    assert(nullifier != 0);

    let _ = (root, l1, n23, n4567, nullifier);
}
