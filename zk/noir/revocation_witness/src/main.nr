fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    revocation_root: pub Field,
    nullifier: pub Field,
    sibling_0: Field,
    sibling_1: Field,
    sibling_2: Field,
    path_bits: u8,
) {
    // Derive credential root from secret (same as silent_witness registration)
    let credential_root = std::hash::pedersen_hash([credential_secret]);

    // Derive revocation-specific nullifier (binds to credential only, not video)
    let derived_nullifier = std::hash::pedersen_hash([credential_secret, nullifier_secret]);
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    // Merkle proof: prove credential_root is a leaf in the tree.
    // Tree depth = 3 → up to 8 revoked credentials per tree.
    //
    // Traversal: path_bits[i] == 0 → current is left child (hash(current, sibling))
    //            path_bits[i] == 1 → current is right child (hash(sibling, current))
    //
    // Only the bottom 3 bits of path_bits are used (values 0-7).
    // Bits 3-7 must be zero; the assert below enforces this.
    assert(path_bits < 8, "path_bits must be in range 0-7 for depth-3 tree");

    let siblings = [sibling_0, sibling_1, sibling_2];

    let mut current = credential_root;
    for i in 0..3 {
        let bit: Field = ((path_bits >> i) & 1) as Field;
        // Arithmetic multiplexer for Merkle path:
        //   bit == 0: hash(current, sibling)  → left=current, right=sibling
        //   bit == 1: hash(sibling, current)  → left=sibling, right=current
        let left = current + bit * (siblings[i] - current);
        let right = siblings[i] + bit * (current - siblings[i]);
        current = std::hash::pedersen_hash([left, right]);
    }

    assert(current == revocation_root, "not in revocation list");
}

// ---------------------------------------------------------------------------
// Test corpus -- Revocation Witness circuit
//
// ALL SECRETS BELOW ARE SYNTHETIC AND FOR TESTING ONLY.
// Do not use these values in any production credential or proof.
//
// The revocation tree for testing uses 8 leaves (depth 3):
//   Leaf 0: root(12345) = credential_root from the base silent_witness fixture
//   Leaf 1: root(99999) = pedersen_hash([99999])
//   Leaf 2: root(88888) = pedersen_hash([88888])
//   Leaf 3: root(77777) = pedersen_hash([77777])
//   Leaf 4: root(66666) = pedersen_hash([66666])
//   Leaf 5: root(55555) = pedersen_hash([55555])
//   Leaf 6: root(44444) = pedersen_hash([44444])
//   Leaf 7: root(33333) = pedersen_hash([33333])
//
// Revocation nullifier = pedersen_hash([credential_secret, nullifier_secret])
//   For (12345, 67890): derived by the helper circuit.
//
// Depth-3 Pedersen Merkle tree:
//   Internal nodes are pedersen_hash([left_child, right_child]).
//   With path_bits = 0, the credential_root is at leaf position 0.
// ---------------------------------------------------------------------------

/// Base fixture: credential_secret = 12345 is at leaf index 0 (path_bits = 0).
#[test]
fn test_valid_revocation_witness() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let sibling0 = std::hash::pedersen_hash([99999]);

    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);

    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);

    let node_01 = std::hash::pedersen_hash([root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    main(cs, ns, tree_root, null, sibling0, sibling1, sibling2, 0);
}

/// Edge case: zero credential_secret with valid Merkle proof.
#[test]
fn test_zero_credential_secret_revocation() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let node_01 = std::hash::pedersen_hash([root, 0]);
    let node_0123 = std::hash::pedersen_hash([node_01, 0]);
    let tree_root = std::hash::pedersen_hash([node_0123, 0]);

    main(cs, ns, tree_root, null, 0, 0, 0, 0);
}

/// Edge case: max field credential_secret.
#[test]
fn test_max_field_credential_secret_revocation() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let node_01 = std::hash::pedersen_hash([root, 0]);
    let node_0123 = std::hash::pedersen_hash([node_01, 0]);
    let tree_root = std::hash::pedersen_hash([node_0123, 0]);

    main(cs, ns, tree_root, null, 0, 0, 0, 0);
}

/// Wrong credential_secret: derived root won't match the Merkle proof.
#[test(should_fail_with = "not in revocation list")]
fn test_wrong_credential_secret_revocation() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let null = std::hash::pedersen_hash([cs, ns]);

    let wrong_cs: Field = 99999;
    let wrong_root = std::hash::pedersen_hash([wrong_cs]);

    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);

    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);

    let node_01 = std::hash::pedersen_hash([wrong_root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    main(99999, ns, tree_root, null, sibling0, sibling1, sibling2, 0);
}

/// Wrong nullifier_secret: nullifier won't match.
#[test(should_fail_with = "nullifier mismatch")]
fn test_wrong_nullifier_secret_revocation() {
    let cs: Field = 12345;
    let root = std::hash::pedersen_hash([cs]);

    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);
    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);
    let node_01 = std::hash::pedersen_hash([root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    let wrong_null = std::hash::pedersen_hash([cs, 11111]);
    main(cs, 11111, tree_root, wrong_null, sibling0, sibling1, sibling2, 0);
}

/// Tampered revocation_root: proof is valid but the public root is wrong.
#[test(should_fail_with = "not in revocation list")]
fn test_tampered_revocation_root() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);
    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);

    main(cs, ns, 0, null, sibling0, sibling1, sibling2, 0);
}

/// Tampered nullifier: correct Merkle proof but wrong public nullifier.
#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_nullifier_revocation() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);

    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);
    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);
    let node_01 = std::hash::pedersen_hash([root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    main(cs, ns, tree_root, 0xDEAD, sibling0, sibling1, sibling2, 0);
}

/// Non-member credential: a valid credential that is NOT in the revocation tree.
#[test(should_fail_with = "not in revocation list")]
fn test_non_member_credential() {
    let non_member: Field = 22222;
    let ns: Field = 67890;
    let null = std::hash::pedersen_hash([non_member, ns]);

    let root = std::hash::pedersen_hash([12345]);
    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);
    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);
    let node_01 = std::hash::pedersen_hash([root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    main(non_member, ns, tree_root, null, sibling0, sibling1, sibling2, 0);
}

/// Wrong path bit: prove membership at index 1 using the same siblings.
#[test(should_fail_with = "not in revocation list")]
fn test_wrong_path_bit() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let sibling0 = std::hash::pedersen_hash([99999]);
    let leaf2 = std::hash::pedersen_hash([88888]);
    let leaf3 = std::hash::pedersen_hash([77777]);
    let sibling1 = std::hash::pedersen_hash([leaf2, leaf3]);
    let leaf4 = std::hash::pedersen_hash([66666]);
    let leaf5 = std::hash::pedersen_hash([55555]);
    let leaf6 = std::hash::pedersen_hash([44444]);
    let leaf7 = std::hash::pedersen_hash([33333]);
    let node_45 = std::hash::pedersen_hash([leaf4, leaf5]);
    let node_67 = std::hash::pedersen_hash([leaf6, leaf7]);
    let sibling2 = std::hash::pedersen_hash([node_45, node_67]);
    let node_01 = std::hash::pedersen_hash([root, sibling0]);
    let node_0123 = std::hash::pedersen_hash([node_01, sibling1]);
    let tree_root = std::hash::pedersen_hash([node_0123, sibling2]);

    main(cs, ns, tree_root, null, sibling0, sibling1, sibling2, 7);
}

/// path_bits out of range (> 7) must be rejected by the range assertion.
#[test(should_fail_with = "path_bits must be in range 0-7 for depth-3 tree")]
fn test_path_bits_out_of_range() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let root = std::hash::pedersen_hash([cs]);
    let null = std::hash::pedersen_hash([cs, ns]);

    let node_01 = std::hash::pedersen_hash([root, 0]);
    let node_0123 = std::hash::pedersen_hash([node_01, 0]);
    let tree_root = std::hash::pedersen_hash([node_0123, 0]);

    main(cs, ns, tree_root, null, 0, 0, 0, 8);
}
