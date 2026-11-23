//! Focused tests for the bounded proof statement compatibility descriptor
//! and fail-closed critical-field validation.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Env};

#[cfg(test)]
fn setup() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn descriptor_reports_bounded_schemas_and_versions() {
    let (_env, client, _admin) = setup();
    let desc = client.get_proof_statement_compatibility();

    assert_eq!(
        desc.descriptor_version,
        verifier_inputs::COMPATIBILITY_DESCRIPTOR_VERSION
    );
    assert_eq!(
        desc.min_verifier_input_version,
        verifier_inputs::MIN_VERIFIER_INPUT_VERSION
    );
    assert_eq!(
        desc.max_verifier_input_version,
        verifier_inputs::MAX_VERIFIER_INPUT_VERSION
    );
    assert_eq!(desc.min_circuit_version, MIN_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(desc.max_circuit_version, MAX_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(desc.min_proof_bytes, verifier_inputs::MIN_PROOF_BYTES);
    assert_eq!(desc.max_proof_bytes, verifier_inputs::MAX_PROOF_BYTES);
    assert_eq!(
        desc.supported_critical_fields,
        verifier_inputs::CRITICAL_FIELDS_ALL_SUPPORTED
    );
    assert!(desc.fail_closed_on_unknown_critical_fields);
    assert!(desc.schemas.len() as usize <= verifier_inputs::MAX_COMPATIBILITY_SCHEMAS);
    assert_eq!(desc.schemas.len(), 3);

    let s0 = desc.schemas.get(0).unwrap();
    assert_eq!(s0.schema_id, SCHEMA_ID_SILENT_WITNESS);
    assert_eq!(
        s0.verifier_input_version,
        verifier_inputs::VERIFIER_INPUT_VERSION_V1
    );
    assert_eq!(s0.circuit_version, 1);
    assert_eq!(
        s0.public_inputs_len,
        verifier_inputs::SILENT_WITNESS_PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        s0.supported_critical_fields,
        verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V1
    );

    let s1 = desc.schemas.get(1).unwrap();
    assert_eq!(s1.schema_id, SCHEMA_ID_REVOCATION_WITNESS);
    assert_eq!(
        s1.verifier_input_version,
        verifier_inputs::VERIFIER_INPUT_VERSION_V1
    );
    assert_eq!(s1.circuit_version, 1);
    assert_eq!(
        s1.public_inputs_len,
        verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        s1.supported_critical_fields,
        verifier_inputs::CRITICAL_FIELDS_REVOCATION_WITNESS_V1
    );

    let s2 = desc.schemas.get(2).unwrap();
    assert_eq!(s2.schema_id, SCHEMA_ID_SILENT_WITNESS_V2);
    assert_eq!(
        s2.verifier_input_version,
        verifier_inputs::VERIFIER_INPUT_VERSION_V2
    );
    assert_eq!(s2.circuit_version, verifier_inputs::EXPECTED_CIRCUIT_VERSION);
    assert_eq!(
        s2.public_inputs_len,
        verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        s2.supported_critical_fields,
        verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V2
    );
}

#[test]
fn check_compatibility_accepts_supported_and_fails_closed_on_unsupported_critical_fields() {
    let (_env, client, _admin) = setup();

    // Supported schemas + matching verifier-input versions + supported critical fields.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V1,
            &verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V1,
        ),
        verifier_inputs::ACCEPTED_CODE
    );
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_REVOCATION_WITNESS,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V1,
            &verifier_inputs::CRITICAL_FIELDS_REVOCATION_WITNESS_V1,
        ),
        verifier_inputs::ACCEPTED_CODE
    );
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS_V2,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V2,
            &verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V2,
        ),
        verifier_inputs::ACCEPTED_CODE
    );

    // Unknown schema fails closed.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &99,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V1,
            &0,
        ),
        RejectCode::UnknownSchema.as_code()
    );

    // Mismatched verifier-input version fails closed.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V2,
            &verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V1,
        ),
        RejectCode::VersionMismatch.as_code()
    );

    // Unknown critical field bit fails closed.
    let unknown_critical_field: u32 = 1 << 30;
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS_V2,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V2,
            &(verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V2 | unknown_critical_field),
        ),
        RejectCode::UnsupportedCriticalField.as_code()
    );

    // Cross-schema critical field (v2-only verifier_scope on v1) fails closed.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V1,
            &(verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V1
                | verifier_inputs::CRITICAL_FIELD_VERIFIER_SCOPE),
        ),
        RejectCode::UnsupportedCriticalField.as_code()
    );
}

#[test]
fn descriptor_and_check_reflect_narrowed_circuit_version_window_and_work_while_paused() {
    let (env, client, admin) = setup();
    let verifier = Address::generate(&env);
    client.set_verifier(&admin, &verifier);
    client.set_verifier_circuit_versions(&admin, &2, &2);

    // Pause all registration domains; read-only compatibility queries must stay callable.
    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &3600);

    let desc = client.get_proof_statement_compatibility();
    assert_eq!(desc.min_circuit_version, 2);
    assert_eq!(desc.max_circuit_version, 2);

    // v1 schema (circuit_version = 1) is now outside the active window.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V1,
            &verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V1,
        ),
        RejectCode::VersionMismatch.as_code()
    );

    // v2 schema (circuit_version = 2) remains accepted.
    assert_eq!(
        client.check_proof_statement_compatibility(
            &SCHEMA_ID_SILENT_WITNESS_V2,
            &verifier_inputs::VERIFIER_INPUT_VERSION_V2,
            &verifier_inputs::CRITICAL_FIELDS_SILENT_WITNESS_V2,
        ),
        verifier_inputs::ACCEPTED_CODE
    );
}
