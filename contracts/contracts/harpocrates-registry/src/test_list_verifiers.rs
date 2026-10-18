#![cfg(test)]

//! Paginated verifier-set inspection (`list_verifiers`, #585).

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

fn setup(env: &Env) -> (HarpocratesRegistryClient<'_>, Address) {
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.init(&admin);
    (client, admin)
}

#[test]
fn empty_registry_returns_empty_page() {
    let env = Env::default();
    let (client, _) = setup(&env);

    let page = client.list_verifiers(&0, &MAX_VERIFIER_LIST_LIMIT);
    assert_eq!(page.entries.len(), 0);
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.total_populated, 0);
}

#[test]
fn lists_active_verifier() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let verifier = Address::generate(&env);
    client.set_verifier(&admin, &verifier);

    let page = client.list_verifiers(&0, &MAX_VERIFIER_LIST_LIMIT);
    assert_eq!(page.total_populated, 1);
    assert_eq!(page.entries.len(), 1);
    let entry = page.entries.get(0).unwrap();
    assert_eq!(entry.address, verifier);
    assert_eq!(entry.role, VerifierRole::Active);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn paginates_rotation_slots_in_order() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let active = Address::generate(&env);
    let pending = Address::generate(&env);
    client.set_verifier(&admin, &active);
    client.schedule_verifier_rotation(&admin, &pending, &100, &10, &10);

    let first = client.list_verifiers(&0, &1);
    assert_eq!(first.total_populated, 3);
    assert_eq!(first.entries.get(0).unwrap().role, VerifierRole::Active);
    let cursor = first.next_cursor.unwrap();

    let second = client.list_verifiers(&cursor, &1);
    let entry = second.entries.get(0).unwrap();
    assert_eq!(entry.role, VerifierRole::Pending);
    assert_eq!(entry.address, pending);

    let third = client.list_verifiers(&second.next_cursor.unwrap(), &1);
    assert_eq!(third.entries.get(0).unwrap().role, VerifierRole::Previous);
    assert_eq!(third.next_cursor, None);
}

#[test]
fn out_of_range_cursor_returns_empty_page() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    client.set_verifier(&admin, &Address::generate(&env));

    let page = client.list_verifiers(&99, &1);
    assert_eq!(page.entries.len(), 0);
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.total_populated, 1);
}

#[test]
fn rejects_zero_and_oversized_limits() {
    let env = Env::default();
    let (client, _) = setup(&env);

    let expected = Err(Ok(soroban_sdk::Error::from_contract_error(
        RegistryError::ListLimitExceeded as u32,
    )));
    assert_eq!(client.try_list_verifiers(&0, &0), expected);
    assert_eq!(
        client.try_list_verifiers(&0, &(MAX_VERIFIER_LIST_LIMIT + 1)),
        expected
    );
}
