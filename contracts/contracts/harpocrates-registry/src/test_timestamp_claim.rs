#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env,
};

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn zero32(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn setup_with_source_proof(
    env: &Env,
) -> (HarpocratesRegistryClient<'_>, Address, Address, BytesN<32>) {
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let source = Address::generate(env);
    client.init(&admin);

    let proof_id = bytes32(env, 11);
    client.register_source(&source, &bytes32(env, 21), &bytes32(env, 22), &proof_id);
    (client, admin, source, proof_id)
}

#[test]
fn anchors_independent_timestamp_claim_with_stellar_source() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(42);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    let digest = bytes32(&env, 77);

    let claim = client.anchor_timestamp_claim(&source, &proof_id, &digest, &0u64, &zero32(&env));

    assert_eq!(claim.proof_id, proof_id);
    assert_eq!(claim.attestation_digest, digest);
    assert_eq!(claim.claimed_time, 0);
    assert_eq!(claim.anchored_at, 1_700_000_000);
    assert_eq!(claim.ledger_sequence, 42);
    assert_eq!(
        claim.sources & TIMESTAMP_SOURCE_STELLAR,
        TIMESTAMP_SOURCE_STELLAR
    );
    assert_eq!(claim.assurance, TIMESTAMP_ASSURANCE_INDEPENDENT);
    assert!(client.has_independent_timestamp_anchor(&proof_id));

    let loaded = client.get_timestamp_claim(&proof_id).expect("claim");
    assert_eq!(loaded.attestation_digest, digest);
}

#[test]
fn anchors_claimed_time_and_rfc3161_commitment() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(7);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    let digest = bytes32(&env, 88);
    let rfc = bytes32(&env, 99);
    let claimed = 1_699_999_900u64;

    let claim = client.anchor_timestamp_claim(&source, &proof_id, &digest, &claimed, &rfc);

    assert_eq!(claim.claimed_time, claimed);
    assert_eq!(
        claim.sources
            & (TIMESTAMP_SOURCE_CLAIMED | TIMESTAMP_SOURCE_STELLAR | TIMESTAMP_SOURCE_RFC3161),
        TIMESTAMP_SOURCE_CLAIMED | TIMESTAMP_SOURCE_STELLAR | TIMESTAMP_SOURCE_RFC3161
    );
    assert_eq!(claim.rfc3161_commitment, rfc);
    assert_eq!(claim.assurance, TIMESTAMP_ASSURANCE_INDEPENDENT);
}

#[test]
fn absence_of_claimed_time_is_valid() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    let claim = client.anchor_timestamp_claim(
        &source,
        &proof_id,
        &bytes32(&env, 55),
        &0u64,
        &zero32(&env),
    );
    assert_eq!(claim.claimed_time, 0);
    assert_eq!(claim.sources & TIMESTAMP_SOURCE_CLAIMED, 0);
    assert!(client.has_independent_timestamp_anchor(&proof_id));
}

#[test]
#[should_panic(expected = "Error(Contract, #72)")]
fn rejects_zero_attestation_digest() {
    let env = Env::default();
    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    client.anchor_timestamp_claim(&source, &proof_id, &zero32(&env), &0u64, &zero32(&env));
}

#[test]
#[should_panic(expected = "Error(Contract, #72)")]
fn rejects_far_future_claimed_time() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    let too_far = 1_700_000_000 + MAX_TIMESTAMP_FUTURE_DRIFT_SECS + 1;
    client.anchor_timestamp_claim(
        &source,
        &proof_id,
        &bytes32(&env, 33),
        &too_far,
        &zero32(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #73)")]
fn rejects_unknown_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.anchor_timestamp_claim(
        &admin,
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &0u64,
        &zero32(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #74)")]
fn rejects_non_upgrade_reanchor() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    let digest = bytes32(&env, 44);
    client.anchor_timestamp_claim(&source, &proof_id, &digest, &0u64, &zero32(&env));
    // Same assurance, no new RFC3161 → rejected
    client.anchor_timestamp_claim(&source, &proof_id, &bytes32(&env, 45), &0u64, &zero32(&env));
}

#[test]
fn allows_rfc3161_upgrade_reanchor() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);

    let (client, _admin, source, proof_id) = setup_with_source_proof(&env);
    client.anchor_timestamp_claim(
        &source,
        &proof_id,
        &bytes32(&env, 44),
        &0u64,
        &zero32(&env),
    );
    let upgraded = client.anchor_timestamp_claim(
        &source,
        &proof_id,
        &bytes32(&env, 45),
        &0u64,
        &bytes32(&env, 90),
    );
    assert_eq!(
        upgraded.sources & TIMESTAMP_SOURCE_RFC3161,
        TIMESTAMP_SOURCE_RFC3161
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #75)")]
fn rejects_unauthorized_actor() {
    let env = Env::default();
    // Do not mock all auths for the unauthorized caller path beyond init/register.
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.init(&admin);
    let proof_id = bytes32(&env, 11);
    client.register_source(&source, &bytes32(&env, 21), &bytes32(&env, 22), &proof_id);

    client.anchor_timestamp_claim(
        &stranger,
        &proof_id,
        &bytes32(&env, 2),
        &0u64,
        &zero32(&env),
    );
}

#[test]
fn has_independent_false_when_missing() {
    let env = Env::default();
    let (client, _admin, _source, proof_id) = setup_with_source_proof(&env);
    assert!(!client.has_independent_timestamp_anchor(&proof_id));
    assert!(client.get_timestamp_claim(&proof_id).is_none());
}
