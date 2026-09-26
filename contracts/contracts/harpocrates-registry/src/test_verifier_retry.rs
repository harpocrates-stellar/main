#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::Address as _,
    Address, Bytes, Env,
};
use verifier_retry::{
    classify_registry_error, VerifierFailureClass, MAX_VERIFIER_INVOKE_ATTEMPTS,
};

#[contract]
struct RetryMockVerifier;

#[contractimpl]
impl RetryMockVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        // Accept the silent-witness layouts the registry forwards.
        if (len != 128 && len != 160 && len != 192 && len != 224) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

#[contract]
struct RetryRejectingVerifier;

#[contractimpl]
impl RetryRejectingVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("rejecting verifier");
    }
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

fn silent_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    domain_tag: &BytesN<32>,
) -> Bytes {
    let mut video_hash_bytes = [0u8; 32];
    video_hash.copy_into_slice(&mut video_hash_bytes);
    let mut credential_root_bytes = [0u8; 32];
    credential_root.copy_into_slice(&mut credential_root_bytes);
    let mut nullifier_bytes = [0u8; 32];
    nullifier.copy_into_slice(&mut nullifier_bytes);
    let mut domain_tag_bytes = [0u8; 32];
    domain_tag.copy_into_slice(&mut domain_tag_bytes);

    let mut bytes = [0u8; 160];
    bytes[16..32].copy_from_slice(&video_hash_bytes[..16]);
    bytes[48..64].copy_from_slice(&video_hash_bytes[16..]);
    bytes[64..96].copy_from_slice(&credential_root_bytes);
    bytes[96..128].copy_from_slice(&nullifier_bytes);
    bytes[128..160].copy_from_slice(&domain_tag_bytes);
    Bytes::from_array(env, &bytes)
}

#[test]
fn retry_policy_view_matches_constants() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&admin);

    let (prefix, max_attempts) = client.get_verifier_retry_policy();
    assert_eq!(prefix, 0x6870782Du32);
    assert_eq!(max_attempts, MAX_VERIFIER_INVOKE_ATTEMPTS);
}

#[test]
fn registry_error_retryable_view_fails_closed() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&admin);

    assert!(!client.is_registry_error_retryable(&7u32));
    assert!(!client.is_registry_error_retryable(&10u32));
    assert!(client.is_registry_error_retryable(&9u32));
    assert!(client.is_registry_error_retryable(&68u32));
    assert!(client.is_registry_error_retryable(&69u32));
    assert!(!client.is_registry_error_retryable(&999u32));

    assert_eq!(
        client.classify_registry_error_class(&7u32),
        VerifierFailureClass::PermanentReject as u32
    );
    assert_eq!(
        client.classify_registry_error_class(&68u32),
        VerifierFailureClass::DependencyFailure as u32
    );
}

#[test]
fn rejecting_verifier_surfaces_invalid_proof() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(RetryRejectingVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 41);
    let credential_root = bytes32(&env, 9);
    let nullifier = bytes32(&env, 42);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 45));

    let result = client.try_register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 43),
        &bytes32(&env, 44),
        &silent_public_inputs(
            &env,
            &video_hash,
            &credential_root,
            &nullifier,
            &expected_domain_tag(&env),
        ),
        &proof_bytes(&env),
    );
    assert!(result.is_err());
    // Same nullifier must remain unused after a permanent reject (no side effects).
    assert!(!client.has_nullifier(&nullifier));
}

#[test]
fn accepting_verifier_still_registers() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(RetryMockVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 51);
    let credential_root = bytes32(&env, 19);
    let nullifier = bytes32(&env, 52);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 55));

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 53),
        &bytes32(&env, 54),
        &silent_public_inputs(
            &env,
            &video_hash,
            &credential_root,
            &nullifier,
            &expected_domain_tag(&env),
        ),
        &proof_bytes(&env),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert!(client.has_nullifier(&nullifier));
}

#[test]
fn classify_table_matches_module() {
    assert_eq!(
        classify_registry_error(RegistryError::InvalidProof as u32),
        VerifierFailureClass::PermanentReject
    );
    assert_eq!(
        classify_registry_error(RegistryError::VerifierDependencyFailure as u32),
        VerifierFailureClass::DependencyFailure
    );
    assert_eq!(
        classify_registry_error(RegistryError::VerifierRetryExhausted as u32),
        VerifierFailureClass::RetryExhausted
    );
}
