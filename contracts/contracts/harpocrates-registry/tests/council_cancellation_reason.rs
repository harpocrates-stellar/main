use harpocrates_registry::{
    CouncilAction, CouncilCancellationReason, HarpocratesRegistry, HarpocratesRegistryClient,
    DEFAULT_TIMELOCK_MIN_DELAY_SECS,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    vec, Address, BytesN, Env, IntoVal as _, Map, Symbol, Val,
};

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn setup() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let m3 = Address::generate(&env);

    client.init(&admin);
    client.set_admin_council(&admin, &vec![&env, m1.clone(), m2.clone(), m3], &2);
    env.ledger()
        .set_timestamp(env.ledger().timestamp() + DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    (env, contract_id, m1, admin)
}

fn propose(client: &HarpocratesRegistryClient<'_>, issuer: &Address, payload: &BytesN<32>) -> u32 {
    client.propose_council_action(
        issuer,
        &(CouncilAction::SetRevocationRoot as u32),
        issuer,
        payload,
    )
}

fn cancellation_reason(env: &Env, data: Val) -> CouncilCancellationReason {
    let data: Map<Symbol, Val> = data.try_into_val(env).unwrap();
    data.get(Symbol::new(env, "reason_code"))
        .unwrap()
        .try_into_val(env)
        .unwrap()
}

#[test]
fn reasoned_cancellation_emits_code_and_keeps_proposal_identity() {
    let (env, contract_id, member, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proposal_id = propose(&client, &member, &b32(&env, 0x89));
    let _ = env.events().all();

    client.cancel_council_proposal_with_reason(
        &member,
        &proposal_id,
        &CouncilCancellationReason::SecurityConcern,
    );

    let events = env.events().all();
    assert_eq!(events.len(), 1);
    let emitted_proposal_id: u32 = events[0].1.get(2).unwrap().try_into_val(&env).unwrap();
    assert_eq!(emitted_proposal_id, proposal_id);
    let reason_code = cancellation_reason(&env, events[0].2.clone());
    assert_eq!(reason_code, CouncilCancellationReason::SecurityConcern);
}

#[test]
fn legacy_cancellation_entrypoint_emits_compatibility_reason() {
    let (env, contract_id, member, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proposal_id = propose(&client, &member, &b32(&env, 0x8A));
    let _ = env.events().all();

    client.cancel_council_proposal(&member, &proposal_id);

    let events = env.events().all();
    assert_eq!(events.len(), 1);
    let reason_code = cancellation_reason(&env, events[0].2.clone());
    assert_eq!(reason_code, CouncilCancellationReason::LegacyUnspecified);
}

#[test]
fn unauthorized_reasoned_cancellation_changes_no_state_or_events() {
    let (env, contract_id, member, _) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proposal_id = propose(&client, &member, &b32(&env, 0x8B));
    let _ = env.events().all();
    let unauthorized = Address::generate(&env);

    let result = client.try_cancel_council_proposal_with_reason(
        &unauthorized,
        &proposal_id,
        &CouncilCancellationReason::Other,
    );

    assert!(result.is_err());
    assert_eq!(env.events().all().len(), 0);
    assert!(!client.get_council_proposal(&proposal_id).unwrap().cancelled);
}
