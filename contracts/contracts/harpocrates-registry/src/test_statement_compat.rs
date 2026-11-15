//! Proof statement compatibility descriptor tests (#1195).
//!
//! Verifies:
//! - `get_statement_compatibility` exposes a bounded descriptor accurately
//!   reflecting accepted schema versions, verifier-input codecs, proof byte
//!   bounds, envelope bounds, and the active verifier circuit-version window.
//! - `check_statement_compat` and `assert_statement_compat` keep unsupported
//!   critical fields, unknown/deprecated schemas, and mismatched or
//!   out-of-window versions strictly fail-closed.

#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[test]
fn test_compatibility_descriptor_reflects_accepted_schemas_and_verifier_window() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    client.init(&admin);
    client.set_verifier(&admin, &verifier);

    let desc = client.get_statement_compatibility();
    assert_eq!(desc.descriptor_version, STATEMENT_COMPAT_DESC_V1);
    assert_eq!(desc.storage_schema_version, SchemaVersion::V2 as u32);
    assert_eq!(desc.min_circuit_version, MIN_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(desc.max_circuit_version, MAX_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(desc.active_min_circuit_ver, 1);
    assert_eq!(desc.active_max_circuit_ver, 2);
    assert_eq!(desc.min_envelope_version, METADATA_ENVELOPE_V1);
    assert_eq!(desc.max_envelope_version, METADATA_ENVELOPE_VERSION_MAX);
    assert_eq!(desc.selective_disc_version, 1);
    assert_eq!(desc.aggregation_version, 1);
    assert_eq!(desc.min_proof_bytes, verifier_inputs::MIN_PROOF_BYTES);
    assert_eq!(desc.max_proof_bytes, verifier_inputs::MAX_PROOF_BYTES);
    assert_eq!(desc.supported_crit_mask, SUPPORTED_CRITICAL_FIELDS_MASK);
    assert!(desc.fail_closed_crit_fields);
    assert!(desc.formats.len() <= MAX_STATEMENT_FORMAT_DESCS);
    assert_eq!(desc.formats.len(), 3);

    let f0 = desc.formats.get(0).unwrap();
    assert_eq!(f0.schema_id, SCHEMA_ID_SILENT_WITNESS);
    assert_eq!(f0.codec_version, 1);
    assert_eq!(f0.circuit_version, 1);
    assert_eq!(f0.primary_byte_len, 160);
    assert_eq!(f0.alt_byte_len, 128);
    assert!(f0.active_in_window);

    let f2 = desc.formats.get(2).unwrap();
    assert_eq!(f2.schema_id, SCHEMA_ID_SILENT_WITNESS_V2);
    assert_eq!(f2.codec_version, 2);
    assert_eq!(f2.circuit_version, 2);
    assert_eq!(f2.primary_byte_len, 256);
    assert!(f2.active_in_window);

    // Narrow the active verifier window to v2-only and confirm descriptor updates live.
    client.set_verifier_circuit_versions(&admin, &2u32, &2u32);
    let narrowed = client.get_statement_compatibility();
    assert_eq!(narrowed.active_min_circuit_ver, 2);
    assert_eq!(narrowed.active_max_circuit_ver, 2);
    assert!(!narrowed.formats.get(0).unwrap().active_in_window);
    assert!(!narrowed.formats.get(1).unwrap().active_in_window);
    assert!(narrowed.formats.get(2).unwrap().active_in_window);
}

#[test]
fn test_unsupported_critical_fields_and_versions_fail_closed() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    client.init(&admin);
    client.set_verifier(&admin, &verifier);

    let schema_hash = b32(&env, 0x77);
    client.add_schema(&admin, &schema_hash, &b32(&env, 0x88), &3u32, &4u32);

    // Supported v2 statement with registered active schema passes.
    let ok_verdict = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS_V2,
        &2u32,
        &METADATA_ENVELOPE_V2,
        &(CRIT_MASK_V2_SCOPED | CRIT_FIELD_SCHEMA_BINDING),
        &Some(schema_hash.clone()),
        &3u32,
    );
    assert_eq!(
        ok_verdict,
        StatementCompatVerdict {
            compatible: true,
            reject_error_code: 0,
            schema_active: true,
        }
    );
    client.assert_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS_V2,
        &2u32,
        &METADATA_ENVELOPE_V2,
        &(CRIT_MASK_V2_SCOPED | CRIT_FIELD_SCHEMA_BINDING),
        &Some(schema_hash.clone()),
        &3u32,
    );

    // 1. Globally unknown critical field bit fails closed (`InvalidPublicInputs` #10).
    let unknown_crit_bit: u32 = 1 << 20;
    let bad_crit = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS_V2,
        &2u32,
        &METADATA_ENVELOPE_V2,
        &unknown_crit_bit,
        &None,
        &0u32,
    );
    assert!(!bad_crit.compatible);
    assert_eq!(
        bad_crit.reject_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(
        client.try_assert_statement_compat(
            &SCHEMA_ID_SILENT_WITNESS_V2,
            &2u32,
            &METADATA_ENVELOPE_V2,
            &unknown_crit_bit,
            &None,
            &0u32,
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidPublicInputs as u32
        )))
    );

    // 2. v2-only critical field (`CRIT_FIELD_VERIFIER_SCOPE`) requested on v1 schema fails closed.
    let v2_crit_on_v1 = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS,
        &1u32,
        &METADATA_ENVELOPE_V1,
        &CRIT_FIELD_VERIFIER_SCOPE,
        &None,
        &0u32,
    );
    assert!(!v2_crit_on_v1.compatible);
    assert_eq!(
        v2_crit_on_v1.reject_error_code,
        RegistryError::InvalidPublicInputs as u32
    );

    // 3. Out-of-window circuit version fails closed (`UnsupportedCircuitVersion` #81).
    client.set_verifier_circuit_versions(&admin, &2u32, &2u32);
    let out_of_window = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS,
        &1u32,
        &METADATA_ENVELOPE_V1,
        &CRIT_MASK_V1_BASE,
        &None,
        &0u32,
    );
    assert!(!out_of_window.compatible);
    assert_eq!(
        out_of_window.reject_error_code,
        RegistryError::UnsupportedCircuitVersion as u32
    );

    // 4. Deprecated schema or mismatched schema version fails closed (#51 / #52).
    let wrong_ver = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS_V2,
        &2u32,
        &METADATA_ENVELOPE_V2,
        &CRIT_MASK_V2_SCOPED,
        &Some(schema_hash.clone()),
        &9u32,
    );
    assert!(!wrong_ver.compatible);
    assert_eq!(
        wrong_ver.reject_error_code,
        RegistryError::SchemaVersionMismatch as u32
    );

    client.deprecate_schema(&admin, &schema_hash);
    let deprecated = client.check_statement_compat(
        &SCHEMA_ID_SILENT_WITNESS_V2,
        &2u32,
        &METADATA_ENVELOPE_V2,
        &CRIT_MASK_V2_SCOPED,
        &Some(schema_hash),
        &3u32,
    );
    assert!(!deprecated.compatible);
    assert_eq!(
        deprecated.reject_error_code,
        RegistryError::InactiveSchema as u32
    );
}
