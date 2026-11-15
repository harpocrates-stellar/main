//! Focused tests for unsupported required proof extensions (#1196).
//!
//! Verifies:
//! - Well-formed required extensions with unknown tags fail closed with the
//!   stable typed error `RegistryError::UnsupportedRequiredExtension` (#113)
//!   and `RejectCode::UnsupportedRequiredExtension` (11).
//! - Version incompatibility (`UnsupportedMetadataEnvelopeVersion` #68 /
//!   `RejectCode::VersionMismatch`) and malformed field encodings
//!   (`InvalidPublicInputs` #10 / `RejectCode::Padding`, `NonCanonicalField`,
//!   `ZeroField`) remain distinct from unsupported required extensions.
//! - Rejecting an extension update preserves the existing `ProofRecord`,
//!   `MetadataEnvelope`, lifecycle history, and previously bound extensions.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

fn canonical_commitment(env: &Env, last_byte: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[31] = last_byte;
    BytesN::from_array(env, &arr)
}

fn non_canonical_commitment(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &verifier_inputs::BN254_SCALAR_FIELD_MODULUS_BE)
}

#[test]
fn test_pure_extension_codec_distinguishes_version_malformed_and_unsupported_required() {
    let mut header = [0u8; 32];
    header[27] = 1; // critical = required
    header[31] = verifier_inputs::PROOF_EXT_TIMESTAMP_ANCHOR as u8;
    let mut commitment = [0u8; 32];
    commitment[31] = 0x42;

    // Supported required extension passes.
    assert_eq!(
        verifier_inputs::validate_extension_field(&header, &commitment, 2, 2),
        Ok((verifier_inputs::PROOF_EXT_TIMESTAMP_ANCHOR, true))
    );

    // 1. Version incompatibility -> VersionMismatch (distinct from malformed & unsupported extension).
    assert_eq!(
        verifier_inputs::validate_extension_field(&header, &commitment, 3, 2),
        Err(RejectCode::VersionMismatch)
    );

    // 2. Malformed field encodings -> NonCanonicalField / Padding / ZeroField.
    assert_eq!(
        verifier_inputs::validate_extension_field(
            &header,
            &verifier_inputs::BN254_SCALAR_FIELD_MODULUS_BE,
            2,
            2,
        ),
        Err(RejectCode::NonCanonicalField)
    );
    let mut bad_padding = header;
    bad_padding[26] = 1;
    assert_eq!(
        verifier_inputs::validate_extension_field(&bad_padding, &commitment, 2, 2),
        Err(RejectCode::Padding)
    );
    let mut zero_tag = header;
    zero_tag[31] = 0;
    assert_eq!(
        verifier_inputs::validate_extension_field(&zero_tag, &commitment, 2, 2),
        Err(RejectCode::ZeroField)
    );

    // 3. Unknown optional extension (critical = 0) is accepted, whereas unknown required (critical = 1) fails closed.
    let mut unknown_optional = [0u8; 32];
    unknown_optional[27] = 0;
    unknown_optional[31] = 99;
    assert_eq!(
        verifier_inputs::validate_extension_field(&unknown_optional, &commitment, 2, 2),
        Ok((99, false))
    );

    let mut unknown_required = unknown_optional;
    unknown_required[27] = 1;
    assert_eq!(
        verifier_inputs::validate_extension_field(&unknown_required, &commitment, 2, 2),
        Err(RejectCode::UnsupportedRequiredExtension)
    );
}

#[test]
fn test_unsupported_required_extension_returns_typed_error_and_preserves_existing_record() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &canonical_commitment(&env, 0xA1));

    let proof_id = canonical_commitment(&env, 0x10);
    let video_hash = canonical_commitment(&env, 0x20);
    let meta_hash = canonical_commitment(&env, 0x30);
    client.register_seal(&issuer, &video_hash, &meta_hash, &proof_id);
    client.bind_metadata_envelope(&issuer, &proof_id, &METADATA_ENVELOPE_V2, &meta_hash);

    // Bind initial supported + optional unknown extensions.
    let mut initial_exts = SorobanVec::new(&env);
    initial_exts.push_back(ProofExtension {
        tag: verifier_inputs::PROOF_EXT_TIMESTAMP_ANCHOR,
        critical: true,
        commitment: canonical_commitment(&env, 0x41),
    });
    initial_exts.push_back(ProofExtension {
        tag: 250, // advisory / non-critical future tag
        critical: false,
        commitment: canonical_commitment(&env, 0x42),
    });
    assert!(client.is_supported_proof_extension(&verifier_inputs::PROOF_EXT_TIMESTAMP_ANCHOR));
    assert!(!client.is_supported_proof_extension(&250));

    let bound =
        client.bind_proof_extensions(&issuer, &proof_id, &METADATA_ENVELOPE_V2, &initial_exts);
    assert_eq!(bound, initial_exts);

    let snapshot_proof = client.get_proof(&proof_id).unwrap();
    let snapshot_env = client.get_metadata_envelope(&proof_id).unwrap();
    let snapshot_history = client.get_proof_history_count(&proof_id);

    // Attempt 1: unsupported required extension -> exact typed error #113.
    let mut unsupported_req = SorobanVec::new(&env);
    unsupported_req.push_back(ProofExtension {
        tag: 999,
        critical: true,
        commitment: canonical_commitment(&env, 0x55),
    });
    let res_unsupported = client.try_bind_proof_extensions(
        &issuer,
        &proof_id,
        &METADATA_ENVELOPE_V2,
        &unsupported_req,
    );
    assert_eq!(
        res_unsupported,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::UnsupportedRequiredExtension as u32
        )))
    );

    // Attempt 2: version incompatibility -> exact typed error #68 (distinct from #113 and #10).
    let res_version =
        client.try_bind_proof_extensions(&issuer, &proof_id, &99u32, &unsupported_req);
    assert_eq!(
        res_version,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::UnsupportedMetadataEnvelopeVersion as u32
        )))
    );

    // Attempt 3: malformed field encoding (non-canonical BN254 commitment or zero tag) -> #10.
    let mut malformed = SorobanVec::new(&env);
    malformed.push_back(ProofExtension {
        tag: 999,
        critical: true,
        commitment: non_canonical_commitment(&env),
    });
    let res_malformed =
        client.try_bind_proof_extensions(&issuer, &proof_id, &METADATA_ENVELOPE_V2, &malformed);
    assert_eq!(
        res_malformed,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidPublicInputs as u32
        )))
    );

    // Existing proof record, status, envelope, history, and prior extensions remain 100% preserved!
    assert_eq!(client.get_proof(&proof_id), Some(snapshot_proof));
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(client.get_metadata_envelope(&proof_id), Some(snapshot_env));
    assert_eq!(client.get_proof_history_count(&proof_id), snapshot_history);
    assert_eq!(client.get_proof_extensions(&proof_id), initial_exts);
}
