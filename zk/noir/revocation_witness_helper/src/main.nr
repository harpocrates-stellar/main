use std::hash::pedersen_hash;

// Protocol revocation witness Merkle-depth bounds (#357).
global MIN_REVOCATION_WITNESS_DEPTH: u32 = 1;
global MAX_REVOCATION_WITNESS_DEPTH: Field = 16;
global MAX_REVOCATION_LEAVES: Field = 65536;
global MAX_REVOCATION_WITNESS_DEPTH_U32: u32 = 16;

fn compute_merkle_root_from_path<let D: u32>(
    leaf: Field,
    path_indices: [Field; D],
    siblings: [Field; D],
    active_depth: u32,
) -> Field {
    assert(active_depth >= MIN_REVOCATION_WITNESS_DEPTH, "depth_undersize");
    assert(active_depth <= MAX_REVOCATION_WITNESS_DEPTH_U32, "depth_oversize");
    assert(active_depth <= D, "depth_oversize");

    let mut current = leaf;
    for i in 0..D {
        if i < active_depth {
            let idx = path_indices[i];
            let sibling = siblings[i];
            let left = if idx == 0 { current } else { sibling };
            let right = if idx == 0 { sibling } else { current };
            current = pedersen_hash([left, right]);
        }
    }
    current
}

fn main() {
    let credential_secret: Field = 12345;
    let nullifier_secret: Field = 67890;

    let credential_root = pedersen_hash([credential_secret]);
    let nullifier = pedersen_hash([credential_secret, nullifier_secret]);

    // Revoked credentials at leaves 0 and 1; remaining leaves are empty (0).
    let leaf_0 = pedersen_hash([111]);
    let leaf_1 = pedersen_hash([222]);
    let leaf_2: Field = 0;
    let leaf_3: Field = 0;
    let leaf_4: Field = 0;
    let leaf_5: Field = 0;
    let leaf_6: Field = 0;
    let leaf_7: Field = 0;

    // Level 1
    let node_01 = pedersen_hash([leaf_0, leaf_1]);
    let node_23 = pedersen_hash([leaf_2, leaf_3]);
    let node_45 = pedersen_hash([leaf_4, leaf_5]);
    let node_67 = pedersen_hash([leaf_6, leaf_7]);

    // Level 2
    let node_0123 = pedersen_hash([node_01, node_23]);
    let node_4567 = pedersen_hash([node_45, node_67]);

    // Root (depth 3 default witness fixture)
    let revocation_root = pedersen_hash([node_0123, node_4567]);

    // Root at maximum depth (depth 16)
    let max_depth_indices: [Field; 16] = [0; 16];
    let max_depth_siblings: [Field; 16] = [
        leaf_1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let max_depth_revocation_root = compute_merkle_root_from_path(
        leaf_0,
        max_depth_indices,
        max_depth_siblings,
        MAX_REVOCATION_WITNESS_DEPTH_U32,
    );

    assert(MAX_REVOCATION_WITNESS_DEPTH == 16);
    assert(MAX_REVOCATION_LEAVES == 65536);

    std::println(f"credential_root = {credential_root}");
    std::println(f"nullifier = {nullifier}");
    std::println(f"leaf_0 = {leaf_0}");
    std::println(f"leaf_1 = {leaf_1}");
    std::println(f"revocation_root = {revocation_root}");
    std::println(f"max_depth_revocation_root = {max_depth_revocation_root}");
}

#[test]
fn print_hashes() {
    main();
}
