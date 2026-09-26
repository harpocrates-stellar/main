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
    pre_image[11..43].copy_from_slice(&a.to_array());
    pre_image[43..75].copy_from_slice(&b.to_array());
    env.crypto().sha256(&Bytes::from_array(env, &pre_image)).into()
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
        &1,
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
        &1,
    );

    let child_output = bytes32(&env, 12);
    let child = client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [mid_output.clone()]),
        &bytes32(&env, 13),
        &Symbol::new(&env, "redact"),
        &child_output,
        &2,
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
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::LineageFanOutExceeded as u32))));
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
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::LineageCycle as u32))));
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
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::LineageEmptyParents as u32))));
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
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::InvalidLineage as u32))));
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
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::LineageParentUnavailable as u32))));
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
        &1,
    );

    let result = client.try_register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent]),
        &bytes32(&env, 6),
        &Symbol::new(&env, "blur"),
        &output,
        &1,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::DuplicateLineage as u32))));
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
        &5,
    );
    assert_eq!(result, Err(Ok(soroban_sdk::Error::from_contract_error(RegistryError::LineageTooDeep as u32))));
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

#[test]
fn paginates_lineage_children_in_registration_order() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = bytes32(&env, 10);

    client.init(&admin);
    client.register_source(&actor, &bytes32(&env, 11), &bytes32(&env, 12), &parent);

    let child_a = bytes32(&env, 20);
    let child_b = bytes32(&env, 21);
    let child_c = bytes32(&env, 22);

    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &bytes32(&env, 30),
        &Symbol::new(&env, "crop"),
        &child_a,
        &1,
    );
    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &bytes32(&env, 31),
        &Symbol::new(&env, "blur"),
        &child_b,
        &1,
    );
    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::from_array(&env, [parent.clone()]),
        &bytes32(&env, 32),
        &Symbol::new(&env, "redact"),
        &child_c,
        &1,
    );

    assert_eq!(client.get_lineage_children_count(&parent), 3);

    let page1 = client.list_lineage_children(&parent, &0, &2);
    assert_eq!(page1.total, 3);
    assert_eq!(page1.next_offset, 2);
    assert_eq!(page1.children.len(), 2);
    assert_eq!(page1.children.get(0).unwrap(), child_a);
    assert_eq!(page1.children.get(1).unwrap(), child_b);

    let page2 = client.list_lineage_children(&parent, &page1.next_offset, &2);
    assert_eq!(page2.total, 3);
    assert_eq!(page2.next_offset, 3);
    assert_eq!(page2.children.len(), 1);
    assert_eq!(page2.children.get(0).unwrap(), child_c);

    let empty = client.list_lineage_children(&parent, &3, &2);
    assert_eq!(empty.total, 3);
    assert_eq!(empty.next_offset, 3);
    assert_eq!(empty.children.len(), 0);

    let unknown = client.list_lineage_children(&bytes32(&env, 99), &0, &10);
    assert_eq!(unknown.total, 0);
    assert_eq!(unknown.children.len(), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #79)")]
fn rejects_zero_children_page_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.list_lineage_children(&bytes32(&env, 1), &0, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #79)")]
fn rejects_oversized_children_page_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.list_lineage_children(&bytes32(&env, 1), &0, &(MAX_LINEAGE_CHILDREN_PAGE + 1));
}
