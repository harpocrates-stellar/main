#![cfg(test)]

use crate::{
    CouncilProposal, DataKey, HarpocratesRegistry, HarpocratesRegistryClient, ProposalAction,
    RegistryError, TimelockProposal, INTENT_QUEUE_ADMIN_TRANSFER, INTENT_QUEUE_COUNCIL,
    INTENT_QUEUE_TIMELOCK, INTENT_ROLE_ADMIN,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn setup() -> (Env, Address, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, client, admin)
}

#[test]
fn binds_privileged_transitions_to_approved_parameters_and_executes_when_matched() {
    let (env, _contract_id, client, admin) = setup();
    let other_contract_id = env.register(HarpocratesRegistry, ());
    let other_client = HarpocratesRegistryClient::new(&env, &other_contract_id);
    other_client.init(&admin);

    let pending_admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let verifier = Address::generate(&env);
    let meta = BytesN::from_array(&env, &[0x66; 32]);
    let zero = BytesN::from_array(&env, &[0u8; 32]);

    client.add_issuer(&admin, &issuer, &meta);

    // 1. Admin transfer digest is bound on-chain and domain-separated by contract address.
    client.propose_admin(&admin, &pending_admin);
    let admin_digest = client.get_admin_intent_digest().unwrap();
    let expected_admin_digest = client.compute_role_intent_digest(
        &INTENT_QUEUE_ADMIN_TRANSFER,
        &0,
        &INTENT_ROLE_ADMIN,
        &admin,
        &pending_admin,
        &zero,
        &1_700_000_000,
    );
    assert_eq!(admin_digest, expected_admin_digest);

    // Cross-contract digest differs for the exact same parameters.
    let other_digest = other_client.compute_role_intent_digest(
        &INTENT_QUEUE_ADMIN_TRANSFER,
        &0,
        &INTENT_ROLE_ADMIN,
        &admin,
        &pending_admin,
        &zero,
        &1_700_000_000,
    );
    assert_ne!(admin_digest, other_digest);

    // 2. Timelock proposal binds `(proposal_id, action, proposer, target, payload, created_at)`.
    let tl_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &verifier,
        &zero,
    );
    let tl_digest = client.get_timelock_intent_digest(&tl_id).unwrap();
    let expected_tl_digest = client.compute_role_intent_digest(
        &INTENT_QUEUE_TIMELOCK,
        &tl_id,
        &(ProposalAction::SetVerifier as u32),
        &admin,
        &verifier,
        &zero,
        &1_700_000_000,
    );
    assert_eq!(tl_digest, expected_tl_digest);

    // Advance past timelock delay and execute with verified intent.
    let min_delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(1_700_000_000 + min_delay + 1);
    client.exec_timelock_with_intent(
        &admin,
        &tl_id,
        &(ProposalAction::SetVerifier as u32),
        &verifier,
        &tl_digest,
    );
    assert_eq!(client.get_verifier(), Some(verifier.clone()));

    // Accept admin transfer with verified intent; clears stored intent digest.
    client.accept_admin_with_intent(&pending_admin, &INTENT_ROLE_ADMIN, &admin_digest);
    assert_eq!(client.get_admin(), Some(pending_admin));
    assert_eq!(client.get_admin_intent_digest(), None);
}

#[test]
fn rejects_substituted_target_roles_and_tampered_parameters_at_execution_time() {
    let (env, contract_id, client, admin) = setup();
    let pending_admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let issuer = Address::generate(&env);
    let verifier = Address::generate(&env);
    let member_1 = Address::generate(&env);
    let member_2 = Address::generate(&env);
    let meta = BytesN::from_array(&env, &[0x77; 32]);
    let zero = BytesN::from_array(&env, &[0u8; 32]);

    client.add_issuer(&admin, &issuer, &meta);
    client.propose_admin(&admin, &pending_admin);
    let admin_digest = client.get_admin_intent_digest().unwrap();

    // 1. Caller presenting a substituted target role (`2` instead of `INTENT_ROLE_ADMIN = 1`)
    // is rejected with `RoleIntentDigestMismatch` (`#113`), leaving `admin` in place.
    assert_eq!(
        client.try_accept_admin_with_intent(&pending_admin, &2, &admin_digest),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );
    assert_eq!(client.get_admin(), Some(admin.clone()));

    // 2. Timelock proposal: queue `SetVerifier` (`1`), then test both caller-side role substitution
    // (`RevokeIssuer = 2`) and storage-level target-role substitution!
    let tl_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &issuer,
        &zero,
    );
    let tl_digest = client.get_timelock_intent_digest(&tl_id).unwrap();

    let min_delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(1_700_000_000 + min_delay + 1);

    // Caller tries to execute expecting `RevokeIssuer (2)` instead of `SetVerifier (1)` -> rejected!
    assert_eq!(
        client.try_exec_timelock_with_intent(
            &admin,
            &tl_id,
            &(ProposalAction::RevokeIssuer as u32),
            &issuer,
            &tl_digest,
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );

    // Simulate a substituted target role (`SetVerifier -> RevokeIssuer`) in queued storage:
    // both `execute_timelocked_proposal` and `emergency_execute_timelock` reject it fail-closed!
    env.as_contract(&contract_id, || {
        let mut p: TimelockProposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(tl_id))
            .unwrap();
        p.action = ProposalAction::RevokeIssuer as u32;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(tl_id), &p);
    });
    assert_eq!(
        client.try_execute_timelocked_proposal(&admin, &tl_id),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );
    assert_eq!(
        client.try_emergency_execute_timelock(&admin, &tl_id),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );
    assert!(client.is_issuer(&issuer));

    // Simulate PendingAdmin target substitution in storage -> `accept_admin` rejects fail-closed!
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &attacker);
    });
    assert_eq!(
        client.try_accept_admin(&attacker),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );
    assert_eq!(client.get_admin(), Some(admin.clone()));

    // 3. Council proposal: approve `SetVerifier (1)` for `verifier`, then reject both explicit
    // role substitution and storage-level `action = RevokeIssuer (2)` substitution!
    let mut members = Vec::new(&env);
    members.push_back(member_1.clone());
    members.push_back(member_2.clone());
    client.set_admin_council(&admin, &members, &2);
    let now_after = env.ledger().timestamp() + min_delay + 1;
    env.ledger().set_timestamp(now_after);

    let cp_id = client.propose_council_action(&member_1, &1, &verifier, &zero);
    let cp_digest = client.get_council_intent_digest(&cp_id).unwrap();
    assert_eq!(
        cp_digest,
        client.compute_role_intent_digest(
            &INTENT_QUEUE_COUNCIL,
            &cp_id,
            &1,
            &member_1,
            &verifier,
            &zero,
            &now_after,
        )
    );
    client.approve_council_proposal(&member_1, &cp_id);
    client.approve_council_proposal(&member_2, &cp_id);

    // Explicit substituted role (`2` = RevokeIssuer instead of `1` = SetVerifier) fails closed!
    assert_eq!(
        client.try_exec_council_with_intent(&member_1, &cp_id, &2, &verifier, &cp_digest),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );

    // Tamper queued council proposal target role (`1 -> 2`) and target (`verifier -> issuer`):
    // `execute_council_proposal` recomputes the intent digest and reverts with `RoleIntentDigestMismatch`!
    env.as_contract(&contract_id, || {
        let mut cp: CouncilProposal = env
            .storage()
            .persistent()
            .get(&DataKey::CouncilProposal(cp_id))
            .unwrap();
        cp.action = 2;
        cp.target = issuer.clone();
        env.storage()
            .persistent()
            .set(&DataKey::CouncilProposal(cp_id), &cp);
    });
    assert_eq!(
        client.try_execute_council_proposal(&member_1, &cp_id),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::RoleIntentDigestMismatch as u32
        )))
    );
    assert!(client.is_issuer(&issuer));
}
