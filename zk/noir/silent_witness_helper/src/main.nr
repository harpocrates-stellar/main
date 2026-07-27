// ---------------------------------------------------------------------------
// Canonical evidence digest algorithm identifier.
// Must match the constant in the silent_witness main circuit.
// ---------------------------------------------------------------------------
global DIGEST_ALGORITHM_SHA256: Field = 0;

fn main(
    credential_secret: Field,
    nullifier_secret: Field,
    video_hash_hi: Field,
    video_hash_lo: Field,
) -> pub (Field, Field) {
    // Commit to the complete canonical evidence digest with algorithm binding.
    // This must match the derivation in the main silent_witness circuit so that
    // the off-chain helper produces the same credential_root and nullifier that
    // the main circuit expects.
    let evidence_digest = std::hash::pedersen_hash([
        DIGEST_ALGORITHM_SHA256,
        video_hash_hi,
        video_hash_lo,
    ]);

    let credential_root = std::hash::pedersen_hash([credential_secret]);
    let nullifier = std::hash::pedersen_hash([
        credential_secret,
        nullifier_secret,
        evidence_digest,
    ]);

    (credential_root, nullifier)
}
