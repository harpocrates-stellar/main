#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env, Symbol};

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn expected_parent_commitment(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    const PREFIX: [u8; 11] = *b"harp_lin_pc";
    let mut pre_image = [0u8; 75];
    pre_image[..11].copy_from_slice(&PREFIX);
    a.copy_into_slice(&mut pre_image[11..43]);
    b.copy_into_slice(&mut pre_image[43..75]);
    env.crypto().sha256(&Bytes::from_array(env, &pre_image))
}

#[test]
fn stores_lineage_parent_commitments_for_proof_parent() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);
    let video = bytes32(&env, 2);
    let metadata = bytes32(&env, 3);

    client.init(&admin);
    client.register_source(&actor, &video, &metadata, &parent);

    let output = bytes32(&env, 5);
    let manifest = bytes32(&env, 4);
    let lineage = client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &manifest,
        &Symbol::new(&env, "crop"),
        &output,
        1,
    );

    let expected = expected_parent_commitment(&env, &video, &metadata);
    assert_eq!(lineage.parent_commitments.len(), 1);
    assert_eq!(lineage.parent_commitments.get(0).unwrap(), expected);
    assert_eq!(lineage.parent_proof_ids.get(0).unwrap(), parent);
    assert_eq!(lineage.output_digest, output);
    assert_eq!(lineage.depth, 1);

    let fetched = client.get_lineage_parent_commitments(&output).unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched.get(0).unwrap(), expected);

    let stored = client.get_lineage(&output).unwrap();
    assert_eq!(stored.parent_commitments, lineage.parent_commitments);
}

#[test]
fn stores_commitments_for_lineage_parent_chain() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let root = bytes32(&env, 1);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &root);

    let mid_manifest = bytes32(&env, 10);
    let mid_output = bytes32(&env, 11);
    let mid = client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [root]),
        &mid_manifest,
        &Symbol::new(&env, "blur"),
        &mid_output,
        1,
    );

    let child_output = bytes32(&env, 12);
    let child = client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [mid_output.clone()]),
        &bytes32(&env, 13),
        &Symbol::new(&env, "redact"),
        &child_output,
        2,
    );

    let expected = expected_parent_commitment(&env, &mid.manifest_digest, &mid.output_digest);
    assert_eq!(child.parent_commitments.get(0).unwrap(), expected);
    assert_eq!(
        client
            .get_lineage_parent_commitments(&child_output)
            .unwrap()
            .get(0)
            .unwrap(),
        expected
    );
}

#[test]
fn rejects_compose_fanout_above_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    for i in 1u8..=5 {
        client.register_source(
            &actor,
            &bytes32(&env, i * 10),
            &bytes32(&env, i * 10 + 1),
            &bytes32(&env, i),
        );
    }

    let parents = soroban_sdk::Vec::from_array(
        &env,
        [
            bytes32(&env, 1),
            bytes32(&env, 2),
            bytes32(&env, 3),
            bytes32(&env, 4),
            bytes32(&env, 5),
        ],
    );

    let result = client.try_register_lineage(
        &actor,
        &parents,
        &bytes32(&env, 6),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 7),
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::LineageFanOutExceeded)));
}

#[test]
fn rejects_self_referential_lineage_cycle() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    let digest = bytes32(&env, 9);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &digest);

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [digest.clone()]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &digest,
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::LineageCycle)));
}

#[test]
fn rejects_empty_parents() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::new(&env),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::LineageEmptyParents)));
}

#[test]
fn rejects_unknown_parent() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    client.init(&admin);

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [bytes32(&env, 1)]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::InvalidLineage)));
}

#[test]
fn rejects_revoked_parent_proof() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &parent);
    client.revoke_proof(&admin, &parent);

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::LineageParentUnavailable)));
}

#[test]
fn rejects_duplicate_lineage_output() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);
    let output = bytes32(&env, 5);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &parent);
    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &output,
        1,
    );

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent]),
        &bytes32(&env, 6),
        &Symbol::new(&env, "blur"),
        &output,
        1,
    );
    assert_eq!(result, Err(Ok(RegistryError::DuplicateLineage)));
}

#[test]
fn rejects_excessive_depth() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 1);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 2), &bytes32(&env, 3), &parent);

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent]),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 5),
        5,
    );
    assert_eq!(result, Err(Ok(RegistryError::LineageTooDeep)));
}

#[test]
fn get_lineage_parent_commitments_missing_is_none() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    assert!(client
        .get_lineage_parent_commitments(&bytes32(&env, 99))
        .is_none());
}
