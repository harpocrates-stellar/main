// =============================================================================
// Redacted Derivative Ancestry - Harpocrates ZK circuit
//
// Proves that a redacted derivative descends from a committed parent evidence
// object without revealing the unredacted parent content, redaction mask
// preimage, or credential secrets.
//
// Public outputs bind:
//   parent_commitment  - Pedersen commitment to parent media hash halves
//   derivative_digest  - digest of the redacted derivative (bound to parent)
//   parameters_digest  - digest of redaction parameters (mask + seed)
//   operation_type     - must equal OP_REDACT
//   ancestry_root      - protocol ancestry statement commitment
//   nullifier          - one-use binder for this ancestry statement
//   depth              - ancestry depth in [1, MAX_ANCESTRY_DEPTH]
//   domain_tag         - protocol / version / network domain separator
//
// Compatible with lineage operation codes used by backend/frontend manifests:
//   crop=0, transcode=1, blur=2, redact=3, compose=4
// =============================================================================

use std::hash::pedersen_hash;

global OP_CROP: Field = 0;
global OP_TRANSCODE: Field = 1;
global OP_BLUR: Field = 2;
global OP_REDACT: Field = 3;
global OP_COMPOSE: Field = 4;

// Domain separators (must be < BN254 scalar field modulus).
global DOMAIN_PARENT_COMMIT: Field = 0x0048505f5245444143545f504152454e545f434f4d4d49545f563100000001;
global DOMAIN_REDACT_PARAMS: Field = 0x0048505f5245444143545f504152414d535f4449474553545f563100000002;
global DOMAIN_DERIVATIVE: Field = 0x0048505f5245444143545f444552495641544956455f563100000000000003;
global DOMAIN_ANCESTRY: Field = 0x0048505f5245444143545f414e4345535452595f5631000000000000000004;
global DOMAIN_NULLIFIER: Field = 0x0048505f5245444143545f4e554c4c49464945525f56310000000000000005;

global DOMAIN_PROTOCOL_FIELD: Field = 0x261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201;
global DOMAIN_VERSION_FIELD: Field = 0x0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623;
global DOMAIN_NETWORK_FIELD: Field = 0x2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f;

global CIRCUIT_VERSION: Field = 1;

fn expected_domain_tag() -> Field {
    pedersen_hash([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD])
}

fn derive_parent_commitment(parent_hash_hi: Field, parent_hash_lo: Field, parent_blinding: Field) -> Field {
    pedersen_hash([DOMAIN_PARENT_COMMIT, parent_hash_hi, parent_hash_lo, parent_blinding])
}

fn derive_parameters_digest(mask_commitment: Field, redaction_seed: Field) -> Field {
    pedersen_hash([DOMAIN_REDACT_PARAMS, mask_commitment, redaction_seed])
}

fn derive_derivative_digest(
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parameters_digest: Field,
    redaction_seed: Field,
) -> Field {
    pedersen_hash([
        DOMAIN_DERIVATIVE,
        parent_hash_hi,
        parent_hash_lo,
        parameters_digest,
        redaction_seed,
    ])
}

fn derive_ancestry_root(
    parent_commitment: Field,
    derivative_digest: Field,
    parameters_digest: Field,
    operation_type: Field,
    depth: Field,
) -> Field {
    pedersen_hash([
        DOMAIN_ANCESTRY,
        parent_commitment,
        derivative_digest,
        parameters_digest,
        operation_type,
        depth,
        CIRCUIT_VERSION,
    ])
}

fn derive_nullifier(
    credential_secret: Field,
    nullifier_secret: Field,
    ancestry_root: Field,
) -> Field {
    pedersen_hash([DOMAIN_NULLIFIER, credential_secret, nullifier_secret, ancestry_root])
}

fn assert_valid_depth(depth: Field) {
    let ok = (depth == 1) | (depth == 2) | (depth == 3) | (depth == 4);
    assert(ok, "ancestry depth out of range");
}

fn main(
    // --- private witness ---
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parent_blinding: Field,
    mask_commitment: Field,
    redaction_seed: Field,
    credential_secret: Field,
    nullifier_secret: Field,
    // --- public statement ---
    parent_commitment: pub Field,
    derivative_digest: pub Field,
    parameters_digest: pub Field,
    operation_type: pub Field,
    ancestry_root: pub Field,
    nullifier: pub Field,
    depth: pub Field,
    domain_tag: pub Field,
) {
    // Operation must be redact - this circuit does not attest crop/blur/etc.
    assert(operation_type == OP_REDACT, "operation must be redact");

    // Bound depth to the lineage graph limit (1..=4).
    assert_valid_depth(depth);

    // Reject zeroed identity / statement fields (stable, privacy-safe failures).
    assert(parent_commitment != 0, "parent commitment must be non-zero");
    assert(derivative_digest != 0, "derivative digest must be non-zero");
    assert(parameters_digest != 0, "parameters digest must be non-zero");
    assert(ancestry_root != 0, "ancestry root must be non-zero");
    assert(nullifier != 0, "nullifier must be non-zero");
    assert(credential_secret != 0, "credential secret must be non-zero");
    assert(nullifier_secret != 0, "nullifier secret must be non-zero");
    assert(parent_blinding != 0, "parent blinding must be non-zero");
    assert(redaction_seed != 0, "redaction seed must be non-zero");

    // Direct cycle: a derivative cannot commit to itself as parent.
    assert(parent_commitment != derivative_digest, "ancestry cycle detected");

    let derived_parent = derive_parent_commitment(parent_hash_hi, parent_hash_lo, parent_blinding);
    assert(derived_parent == parent_commitment, "parent commitment mismatch");

    let derived_params = derive_parameters_digest(mask_commitment, redaction_seed);
    assert(derived_params == parameters_digest, "parameters digest mismatch");

    let derived_derivative = derive_derivative_digest(
        parent_hash_hi,
        parent_hash_lo,
        derived_params,
        redaction_seed,
    );
    assert(derived_derivative == derivative_digest, "derivative digest mismatch");

    let derived_root = derive_ancestry_root(
        derived_parent,
        derived_derivative,
        derived_params,
        OP_REDACT,
        depth,
    );
    assert(derived_root == ancestry_root, "ancestry root mismatch");

    let derived_nullifier = derive_nullifier(credential_secret, nullifier_secret, derived_root);
    assert(derived_nullifier == nullifier, "nullifier mismatch");

    let expected = expected_domain_tag();
    assert(domain_tag == expected, "domain tag mismatch");

    // Silence unused op constants (kept for documentation / future circuits).
    let _ = (OP_CROP, OP_TRANSCODE, OP_BLUR, OP_COMPOSE);
}

// ---------------------------------------------------------------------------
// Synthetic test corpus - ALL SECRETS ARE FOR TESTING ONLY.
// Base fixture:
//   parent_hash_hi   = 11111
//   parent_hash_lo   = 22222
//   parent_blinding  = 33333
//   mask_commitment  = 44444
//   redaction_seed   = 55555
//   credential_secret = 12345
//   nullifier_secret  = 67890
//   depth = 1
// ---------------------------------------------------------------------------

global TEST_PHI: Field = 11111;
global TEST_PLO: Field = 22222;
global TEST_BLIND: Field = 33333;
global TEST_MASK: Field = 44444;
global TEST_SEED: Field = 55555;
global TEST_CS: Field = 12345;
global TEST_NS: Field = 67890;
global TEST_DEPTH: Field = 1;

fn fixture_publics() -> (Field, Field, Field, Field, Field, Field, Field) {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let root = derive_ancestry_root(parent, deriv, params, OP_REDACT, TEST_DEPTH);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    let domain = expected_domain_tag();
    (parent, deriv, params, root, nullifier, TEST_DEPTH, domain)
}

#[test]
fn test_valid_redacted_ancestry() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test]
fn test_valid_depth_boundary_max() {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let depth: Field = 4;
    let root = derive_ancestry_root(parent, deriv, params, OP_REDACT, depth);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        expected_domain_tag(),
    );
}

#[test(should_fail_with = "operation must be redact")]
fn test_rejects_non_redact_operation() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_CROP,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "ancestry depth out of range")]
fn test_rejects_zero_depth() {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let depth: Field = 0;
    let root = derive_ancestry_root(parent, deriv, params, OP_REDACT, depth);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        expected_domain_tag(),
    );
}

#[test(should_fail_with = "ancestry depth out of range")]
fn test_rejects_oversized_depth() {
    let parent = derive_parent_commitment(TEST_PHI, TEST_PLO, TEST_BLIND);
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let depth: Field = 5;
    let root = derive_ancestry_root(parent, deriv, params, OP_REDACT, depth);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        expected_domain_tag(),
    );
}

#[test(should_fail_with = "parent commitment mismatch")]
fn test_rejects_wrong_parent_opening() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        99999,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "parameters digest mismatch")]
fn test_rejects_wrong_redaction_params() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        99999,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "parent commitment mismatch")]
fn test_rejects_swapped_parent_hash_halves() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PLO,
        TEST_PHI,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "derivative digest mismatch")]
fn test_rejects_forged_derivative_digest() {
    let (parent, _deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        0xbeef,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "nullifier mismatch")]
fn test_rejects_wrong_nullifier() {
    let (parent, deriv, params, root, _nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        0xdead,
        depth,
        domain,
    );
}

#[test(should_fail_with = "domain tag mismatch")]
fn test_rejects_wrong_domain_tag() {
    let (parent, deriv, params, root, nullifier, depth, _domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        0xbad,
    );
}

#[test(should_fail_with = "ancestry cycle detected")]
fn test_rejects_direct_cycle() {
    let params = derive_parameters_digest(TEST_MASK, TEST_SEED);
    let deriv = derive_derivative_digest(TEST_PHI, TEST_PLO, params, TEST_SEED);
    let forged_parent = deriv;
    let root = derive_ancestry_root(forged_parent, deriv, params, OP_REDACT, TEST_DEPTH);
    let nullifier = derive_nullifier(TEST_CS, TEST_NS, root);
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        forged_parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        TEST_DEPTH,
        expected_domain_tag(),
    );
}

#[test(should_fail_with = "credential secret must be non-zero")]
fn test_rejects_zero_credential_secret() {
    let (parent, deriv, params, root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        0,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        root,
        nullifier,
        depth,
        domain,
    );
}

#[test(should_fail_with = "ancestry root mismatch")]
fn test_rejects_tampered_ancestry_root() {
    let (parent, deriv, params, _root, nullifier, depth, domain) = fixture_publics();
    main(
        TEST_PHI,
        TEST_PLO,
        TEST_BLIND,
        TEST_MASK,
        TEST_SEED,
        TEST_CS,
        TEST_NS,
        parent,
        deriv,
        params,
        OP_REDACT,
        0xcafe,
        nullifier,
        depth,
        domain,
    );
}
