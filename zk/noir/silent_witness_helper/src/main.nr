// Silent Witness helper circuit — computes public inputs for the main circuit.
//
// Returns (credential_root, nullifier, domain_tag) so the browser client
// obtains all three public values in a single Noir execution without needing
// to replicate the Pedersen hash outside of Noir.
//
// domain_tag = pedersen_hash([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD])
//
// The three domain constants MUST match those embedded in silent_witness/src/main.nr.
// When the circuit version is bumped, update DOMAIN_VERSION_FIELD in both files.

global DOMAIN_PROTOCOL_FIELD: Field =
    0x261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c21;
global DOMAIN_VERSION_FIELD: Field =
    0x0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623;
global DOMAIN_NETWORK_FIELD: Field =
    0x2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a5f;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: Field,
    video_hash_lo: Field,
) -> pub (Field, Field, Field) {
    let credential_root = std::hash::pedersen_hash([credential_secret]);
    let nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        video_hash_hi,
        video_hash_lo,
    ]);
    let domain_tag = std::hash::pedersen_hash([
        DOMAIN_PROTOCOL_FIELD,
        DOMAIN_VERSION_FIELD,
        DOMAIN_NETWORK_FIELD,
    ]);

    (credential_root, nullifier, domain_tag)
}
