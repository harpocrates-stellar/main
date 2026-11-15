//! Tests for bounded public-input and metadata size policy read methods (#1202).

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, Env,
};

#[test]
fn get_input_size_policy_returns_versioned_canonical_limits() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Bounded read works even before `init` is called, without touching storage.
    let policy = client.get_input_size_policy();

    assert_eq!(policy.schema_version, INPUT_SIZE_POLICY_SCHEMA_VERSION);
    assert_eq!(policy.schema_version, 1);
    assert_eq!(policy.min_proof_bytes, verifier_inputs::MIN_PROOF_BYTES);
    assert_eq!(policy.max_proof_bytes, verifier_inputs::MAX_PROOF_BYTES);
    assert_eq!(
        policy.silent_witness_v1_bytes,
        verifier_inputs::PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        policy.silent_witness_v2_bytes,
        verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        policy.silent_witness_browser_bytes,
        SILENT_WITNESS_BROWSER_V1_PUBLIC_INPUTS_LEN
    );
    assert_eq!(
        policy.revocation_witness_bytes,
        verifier_inputs::REVOCATION_PUBLIC_INPUTS_LEN as u32
    );
    assert_eq!(
        policy.selective_disclosure_bytes,
        SELECTIVE_DISCLOSURE_PUBLIC_INPUTS_LEN
    );
    assert_eq!(policy.max_batch_aggregation_size, MAX_AGGREGATION_SIZE);
    assert_eq!(
        policy.max_aggregated_inputs_bytes,
        MAX_AGGREGATED_PUBLIC_INPUTS_LEN
    );
    assert_eq!(
        policy.max_aggregated_inputs_bytes,
        32 + (policy.max_batch_aggregation_size * 128)
    );
    assert_eq!(
        policy.max_metadata_hash_bytes,
        MAX_EVIDENCE_METADATA_HASH_BYTES
    );
    assert_eq!(policy.metadata_envelope_min_version, METADATA_ENVELOPE_V1);
    assert_eq!(
        policy.metadata_envelope_max_version,
        METADATA_ENVELOPE_VERSION_MAX
    );
    assert_eq!(policy.max_lineage_payload_bytes, MAX_LINEAGE_PAYLOAD_BYTES);
    assert_eq!(
        policy.max_source_batch_proof_len,
        MAX_SOURCE_BATCH_PROOF_LEN
    );
}

#[test]
fn get_input_size_policy_stays_callable_when_paused_and_emits_no_events() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &3600);

    let policy = client.get_input_size_policy();
    assert!(env.events().all().events().is_empty());
    assert_eq!(policy.schema_version, 1);
    assert_eq!(policy.max_metadata_hash_bytes, 32);
}

#[test]
fn get_schema_input_limit_maps_every_known_selector_and_returns_none_for_unknown() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let policy = client.get_input_size_policy();

    assert_eq!(
        client.get_schema_input_limit(&SCHEMA_ID_SILENT_WITNESS),
        Some(policy.silent_witness_v1_bytes)
    );
    assert_eq!(
        client.get_schema_input_limit(&SCHEMA_ID_REVOCATION_WITNESS),
        Some(policy.revocation_witness_bytes)
    );
    assert_eq!(
        client.get_schema_input_limit(&SCHEMA_ID_SILENT_WITNESS_V2),
        Some(policy.silent_witness_v2_bytes)
    );
    assert_eq!(
        client.get_schema_input_limit(&SCHEMA_ID_SILENT_WITNESS_BROWSER_V1),
        Some(policy.silent_witness_browser_bytes)
    );
    assert_eq!(
        client.get_schema_input_limit(&SCHEMA_ID_SELECTIVE_DISCLOSURE),
        Some(policy.selective_disclosure_bytes)
    );

    // Boundary / failure-free unknown selectors: returns `None` instead of reverting.
    assert_eq!(client.get_schema_input_limit(&0), None);
    assert_eq!(client.get_schema_input_limit(&6), None);
    assert_eq!(client.get_schema_input_limit(&u32::MAX), None);
}

#[test]
fn policy_boundaries_align_with_on_chain_classifier_rejection_edges() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let policy = client.get_input_size_policy();

    // Exact +1 / -1 frame-length boundaries fail with `RejectCode::Length`.
    let one_over_v1 = Bytes::from_slice(&env, &[0u8; 161]);
    let one_under_v1 = Bytes::from_slice(&env, &[0u8; 159]);
    assert_eq!(one_over_v1.len(), policy.silent_witness_v1_bytes + 1);
    assert_eq!(one_under_v1.len(), policy.silent_witness_v1_bytes - 1);
    assert_eq!(
        client.classify_public_inputs(
            &SCHEMA_ID_SILENT_WITNESS,
            &one_over_v1,
            &policy.min_proof_bytes
        ),
        RejectCode::Length.as_code()
    );
    assert_eq!(
        client.classify_public_inputs(
            &SCHEMA_ID_SILENT_WITNESS,
            &one_under_v1,
            &policy.min_proof_bytes
        ),
        RejectCode::Length.as_code()
    );

    let one_over_v2 = Bytes::from_slice(&env, &[0u8; 257]);
    assert_eq!(one_over_v2.len(), policy.silent_witness_v2_bytes + 1);
    assert_eq!(
        client.classify_public_inputs(
            &SCHEMA_ID_SILENT_WITNESS_V2,
            &one_over_v2,
            &policy.min_proof_bytes
        ),
        RejectCode::Length.as_code()
    );

    // Proof length boundaries: `min_proof_bytes - 1` and `max_proof_bytes + 1`
    // match the exact proof bounds enforced by `verifier_inputs::check_proof_bounds`.
    assert_eq!(
        verifier_inputs::check_proof_bounds(policy.min_proof_bytes),
        Ok(())
    );
    assert_eq!(
        verifier_inputs::check_proof_bounds(policy.max_proof_bytes),
        Ok(())
    );
    assert_eq!(
        verifier_inputs::check_proof_bounds(policy.min_proof_bytes - 1),
        Err(RejectCode::ProofUndersize)
    );
    assert_eq!(
        verifier_inputs::check_proof_bounds(policy.max_proof_bytes + 1),
        Err(RejectCode::ProofOversize)
    );

    // Metadata envelope version boundaries align with `is_supported_envelope_version`.
    assert!(client.is_supported_envelope_version(&policy.metadata_envelope_min_version));
    assert!(client.is_supported_envelope_version(&policy.metadata_envelope_max_version));
    assert!(!client.is_supported_envelope_version(&(policy.metadata_envelope_min_version - 1)));
    assert!(!client.is_supported_envelope_version(&(policy.metadata_envelope_max_version + 1)));
}
