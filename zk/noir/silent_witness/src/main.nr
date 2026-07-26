use std::hash::pedersen_hash;

// ---------------------------------------------------------------------------
// Scoped Nullifier Domain Separator v1
//
// "HARPOCRATES_SCOPED_NULLIFIER_V1" encoded as a 32-byte BN254 field element
// (31 ASCII bytes with a leading 0x00 pad).
//
// Layout:
//   [ 0.. 1)  leading zero (BN254 field padding)
//   [ 1..32)  "HARPOCRATES_SCOPED_NULLIFIER_V1" (31 ASCII bytes)
// ---------------------------------------------------------------------------
global SCOPED_NULLIFIER_V1: Field = 0x00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631;

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
    let derived_root = pedersen_hash([credential_secret]);

    // Scoped nullifier derivation:
    //   scope_hash     = pedersen_hash([domain, verifier_scope, epoch])
    //   nullifier      = pedersen_hash([cs, ns, vhi, vlo, scope_hash])
    let scope_hash = pedersen_hash([SCOPED_NULLIFIER_V1, verifier_scope, epoch]);
    let derived_nullifier = pedersen_hash([
        credential_secret,
        nullifier_secret,
        video_hash_hi,
        video_hash_lo,
        scope_hash,
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
//   credential_secret = 12345
//   nullifier_secret  = 67890
//   video_hash_hi     = 22685491128062564230891640495451214097
//   video_hash_lo     = 45370982256125128461783280990902428194
//   verifier_scope    = 0  (global / unscoped)
//   epoch             = 0  (no epoch / eternal)
//
// Derived public inputs (BN254/UltraHonk, Pedersen):
//   credential_root = pedersen_hash([12345])
//   scope_hash      = pedersen_hash([SCOPED_NULLIFIER_V1, 0, 0])
//   nullifier       = pedersen_hash([12345, 67890, vhi, vlo, scope_hash])
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
fn test_valid_witness_global_scope() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// Positive: explicit verifier scope, epoch 1.
#[test]
fn test_valid_witness_scoped_epoch_1() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 1111;
    let ep: Field = 1;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// Edge: zero credential_secret is a valid field element.
#[test]
fn test_zero_credential_secret() {
    let cs: Field = 0;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// Edge: max-field credential_secret (BN254 prime - 1).
#[test]
fn test_max_field_credential_secret() {
    let cs: Field = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// Edge: all-zero video hash (e.g. blank-frame video) with correct secrets.
#[test]
fn test_zero_video_hash() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 0;
    let vlo: Field = 0;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
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

#[test(should_fail_with = "nullifier mismatch")]
fn test_nullifier_from_different_video() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    // Nullifier computed for a different video
    let nul = compute_scoped_nullifier(cs, ns, 11111111111111111111111111111111111111, 22222222222222222222222222222222222222, scope, ep);
    main(cs, ns, vhi, vlo, root, nul, scope, ep);
}

// ============================================================
// Negative -- scope public input tampering
// ============================================================

// Correct nullifier for scope=0, but scope public input is tampered to 1.
#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_scope_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 0;
    let ep: Field = 0;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Pass scope=1 as public input but nullifier was for scope=0
    main(cs, ns, vhi, vlo, root, nul, 1, ep);
}

// Correct nullifier for epoch=1, but epoch public input is tampered to 0.
#[test(should_fail_with = "nullifier mismatch")]
fn test_tampered_epoch_public_input() {
    let cs: Field = 12345;
    let ns: Field = 67890;
    let vhi: Field = 22685491128062564230891640495451214097;
    let vlo: Field = 45370982256125128461783280990902428194;
    let scope: Field = 42;
    let ep: Field = 1;
    let root = pedersen_hash([cs]);
    let nul = compute_scoped_nullifier(cs, ns, vhi, vlo, scope, ep);
    // Pass epoch=0 as public input but nullifier was for epoch=1
    main(cs, ns, vhi, vlo, root, nul, scope, 0);
}
