// Helper for redacted_ancestry: derives public statement fields from private
// openings. Must stay compatible with the main circuit derivations.

use std::hash::pedersen_hash;

global OP_REDACT: Field = 3;

global DOMAIN_PARENT_COMMIT: Field = 0x0048505f5245444143545f504152454e545f434f4d4d49545f563100000001;
global DOMAIN_REDACT_PARAMS: Field = 0x0048505f5245444143545f504152414d535f4449474553545f563100000002;
global DOMAIN_DERIVATIVE: Field = 0x0048505f5245444143545f444552495641544956455f563100000000000003;
global DOMAIN_ANCESTRY: Field = 0x0048505f5245444143545f414e4345535452595f5631000000000000000004;
global DOMAIN_NULLIFIER: Field = 0x0048505f5245444143545f4e554c4c49464945525f56310000000000000005;

global DOMAIN_PROTOCOL_FIELD: Field = 0x261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201;
global DOMAIN_VERSION_FIELD: Field = 0x0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623;
global DOMAIN_NETWORK_FIELD: Field = 0x2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f;

global CIRCUIT_VERSION: Field = 1;

fn main(
    parent_hash_hi: Field,
    parent_hash_lo: Field,
    parent_blinding: Field,
    mask_commitment: Field,
    redaction_seed: Field,
    credential_secret: Field,
    nullifier_secret: Field,
    depth: Field,
) -> pub (Field, Field, Field, Field, Field, Field, Field) {
    let parent_commitment = pedersen_hash([
        DOMAIN_PARENT_COMMIT,
        parent_hash_hi,
        parent_hash_lo,
        parent_blinding,
    ]);
    let parameters_digest = pedersen_hash([
        DOMAIN_REDACT_PARAMS,
        mask_commitment,
        redaction_seed,
    ]);
    let derivative_digest = pedersen_hash([
        DOMAIN_DERIVATIVE,
        parent_hash_hi,
        parent_hash_lo,
        parameters_digest,
        redaction_seed,
    ]);
    let ancestry_root = pedersen_hash([
        DOMAIN_ANCESTRY,
        parent_commitment,
        derivative_digest,
        parameters_digest,
        OP_REDACT,
        depth,
        CIRCUIT_VERSION,
    ]);
    let nullifier = pedersen_hash([
        DOMAIN_NULLIFIER,
        credential_secret,
        nullifier_secret,
        ancestry_root,
    ]);
    let domain_tag = pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);
    (
        parent_commitment,
        derivative_digest,
        parameters_digest,
        ancestry_root,
        nullifier,
        depth,
        domain_tag,
    )
}

#[test]
fn test_helper_produces_nonzero_publics() {
    let (parent, deriv, params, root, nullifier, depth, domain) = main(
        11111,
        22222,
        33333,
        44444,
        55555,
        12345,
        67890,
        1,
    );
    assert(parent != 0);
    assert(deriv != 0);
    assert(params != 0);
    assert(root != 0);
    assert(nullifier != 0);
    assert(depth == 1);
    assert(domain != 0);
}
