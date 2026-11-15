//! Revision-checked institutional role transition queuing tests (#1190).
//!
//! Uses synthetic addresses and hashes only — no real media, witness values,
//! credentials, or private keys are present.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let cid = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, cid, admin)
}

#[test]
fn stale_and_future_authority_revisions_reject_intent_and_preserve_queued_transfer() {
    let (env, cid, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);

    assert_eq!(client.get_authority_revision(), 1);

    // Wrong revision before anything is queued fails with AuthorityRevisionMismatch.
    assert_eq!(
        client.try_queue_admin_transfer(&admin, &candidate_a, &0),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::AuthorityRevisionMismatch as u32
        )))
    );
    assert_eq!(
        client.try_queue_admin_transfer(&admin, &candidate_a, &2),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::AuthorityRevisionMismatch as u32
        )))
    );
    assert_eq!(client.get_pending_admin(), None);

    // Queue valid transfer at revision 1.
    let queued = client.queue_admin_transfer(&admin, &candidate_a, &1);
    assert_eq!(queued.revision, 1);
    assert_eq!(queued.subject, candidate_a);

    // Stale revision attempt for candidate_b preserves candidate_a!
    assert_eq!(
        client.try_queue_admin_transfer(&admin, &candidate_b, &99),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::AuthorityRevisionMismatch as u32
        )))
    );
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));
    assert_eq!(client.get_queued_admin_transition(), Some(queued.clone()));

    // Compatible retry for candidate_a at revision 1 returns the preserved record!
    let retry = client.queue_admin_transfer(&admin, &candidate_a, &1);
    assert_eq!(retry, queued);
}

#[test]
fn conflicting_admin_and_issuer_transitions_at_same_revision_revert_and_preserve_existing() {
    let (env, cid, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &cid);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);
    let issuer_one = Address::generate(&env);
    let issuer_two = Address::generate(&env);

    client.add_issuer(&admin, &issuer_one, &b32(&env, 0x11));
    client.add_issuer(&admin, &issuer_two, &b32(&env, 0x22));
    let rev = client.get_authority_revision();
    assert_eq!(rev, 3);

    // 1. Queue admin transfer to candidate_a at rev 3.
    let admin_intent = client.queue_admin_transfer(&admin, &candidate_a, &rev);

    // Conflicting admin transfer to candidate_b at rev 3 reverts and preserves candidate_a.
    assert_eq!(
        client.try_queue_admin_transfer(&admin, &candidate_b, &rev),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ConflictingQueuedTransition as u32
        )))
    );
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));
    assert_eq!(
        client.get_queued_admin_transition(),
        Some(admin_intent.clone())
    );

    // Conflicting AddIssuer intent on pending admin candidate_a reverts and preserves candidate_a.
    assert_eq!(
        client.try_queue_role_transition(
            &admin,
            &candidate_a,
            &ROLE_INTENT_ADD_ISSUER,
            &b32(&env, 0x33),
            &rev,
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ConflictingQueuedTransition as u32
        )))
    );
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));

    // 2. Compatible non-conflicting transition on issuer_one at rev 3 succeeds AND preserves admin_intent!
    let revoke_one = client.queue_role_transition(
        &admin,
        &issuer_one,
        &ROLE_INTENT_REVOKE_ISSUER,
        &b32(&env, 0x00),
        &rev,
    );
    assert!(revoke_one.proposal_id > 0);
    assert_eq!(
        client.get_queued_admin_transition(),
        Some(admin_intent.clone())
    );
    assert_eq!(
        client.get_queued_role_transition(&issuer_one),
        Some(revoke_one.clone())
    );

    // Conflicting AddIssuer on issuer_one while RevokeIssuer is queued fails and preserves revoke_one!
    assert_eq!(
        client.try_queue_role_transition(
            &admin,
            &issuer_one,
            &ROLE_INTENT_ADD_ISSUER,
            &b32(&env, 0x44),
            &rev,
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ConflictingQueuedTransition as u32
        )))
    );
    assert_eq!(
        client.get_queued_role_transition(&issuer_one),
        Some(revoke_one.clone())
    );

    // Compatible transition on distinct subject issuer_two succeeds alongside both!
    let revoke_two = client.queue_role_transition(
        &admin,
        &issuer_two,
        &ROLE_INTENT_REVOKE_ISSUER,
        &b32(&env, 0x00),
        &rev,
    );
    assert_eq!(
        client.get_queued_role_transition(&issuer_one),
        Some(revoke_one)
    );
    assert_eq!(
        client.get_queued_role_transition(&issuer_two),
        Some(revoke_two)
    );

    // Accepting admin transfer bumps authority revision, invalidating stale expected_revision = 3.
    client.accept_admin(&candidate_a);
    assert_eq!(client.get_authority_revision(), rev + 1);
    assert_eq!(client.get_queued_admin_transition(), None);
    assert_eq!(
        client.try_queue_admin_transfer(&candidate_a, &candidate_b, &rev),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::AuthorityRevisionMismatch as u32
        )))
    );
}
