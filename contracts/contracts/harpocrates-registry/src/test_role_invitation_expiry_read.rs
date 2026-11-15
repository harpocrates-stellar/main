#![cfg(test)]

use crate::{
    DataKey, HarpocratesRegistry, HarpocratesRegistryClient, RegistryError, RoleInvitationRecord,
    RoleInvitationState, INVITE_ROLE_ADMIN, INVITE_ROLE_GUARDIAN, INVITE_ROLE_ISSUER,
    MAX_ROLE_INVITATION_TTL_SECS,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Env,
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
fn returns_nonexistent_active_and_expired_consistently_across_role_kinds() {
    let (env, _contract_id, client, admin) = setup();
    let cand_admin = Address::generate(&env);
    let cand_issuer = Address::generate(&env);
    let cand_guardian = Address::generate(&env);
    let stranger = Address::generate(&env);

    // 1. Nonexistent before any invitation exists.
    let missing_admin = client.get_admin_invitation_status();
    assert_eq!(missing_admin.state, RoleInvitationState::Nonexistent);
    assert_eq!(missing_admin.candidate, None);
    assert_eq!(missing_admin.expires_at, 0);

    let missing_issuer = client.get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer);
    assert_eq!(missing_issuer.state, RoleInvitationState::Nonexistent);
    assert_eq!(missing_issuer.candidate, None);

    // 2. Unbounded legacy `propose_admin` reports Active with `expires_at == 0`.
    client.propose_admin(&admin, &cand_admin);
    let unbounded = client.get_admin_invitation_status();
    assert_eq!(unbounded.state, RoleInvitationState::Active);
    assert_eq!(unbounded.candidate, Some(cand_admin.clone()));
    assert_eq!(unbounded.invited_at, 1_700_000_000);
    assert_eq!(unbounded.expires_at, 0);

    // Querying a different candidate for INVITE_ROLE_ADMIN still reports Nonexistent.
    let other_admin_check = client.get_role_invitation_status(&INVITE_ROLE_ADMIN, &stranger);
    assert_eq!(other_admin_check.state, RoleInvitationState::Nonexistent);

    // 3. Bounded TTL invitations transition Active -> Expired at exact `expires_at` boundary.
    client.propose_admin_expiring(&admin, &cand_admin, &300);
    client.invite_role_candidate(&admin, &INVITE_ROLE_ISSUER, &cand_issuer, &300);
    client.invite_role_candidate(&admin, &INVITE_ROLE_GUARDIAN, &cand_guardian, &600);

    env.ledger().set_timestamp(1_700_000_299);
    assert_eq!(
        client.get_admin_invitation_status().state,
        RoleInvitationState::Active
    );
    assert_eq!(
        client
            .get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer)
            .state,
        RoleInvitationState::Active
    );

    // Exact deadline `now == expires_at` is Expired (`1_700_000_300`), while guardian (`600`) stays Active.
    env.ledger().set_timestamp(1_700_000_300);
    let exp_admin = client.get_admin_invitation_status();
    assert_eq!(exp_admin.state, RoleInvitationState::Expired);
    assert_eq!(exp_admin.candidate, Some(cand_admin.clone()));
    assert_eq!(exp_admin.expires_at, 1_700_000_300);

    let exp_issuer = client.get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer);
    assert_eq!(exp_issuer.state, RoleInvitationState::Expired);
    assert_eq!(exp_issuer.candidate, Some(cand_issuer.clone()));
    assert_eq!(exp_issuer.expires_at, 1_700_000_300);

    let active_guardian = client.get_role_invitation_status(&INVITE_ROLE_GUARDIAN, &cand_guardian);
    assert_eq!(active_guardian.state, RoleInvitationState::Active);
}

#[test]
fn read_methods_never_mutate_storage_or_emit_hidden_cleanup_events() {
    let (env, contract_id, client, admin) = setup();
    let cand_admin = Address::generate(&env);
    let cand_issuer = Address::generate(&env);

    client.propose_admin_expiring(&admin, &cand_admin, &120);
    client.invite_role_candidate(&admin, &INVITE_ROLE_ISSUER, &cand_issuer, &120);

    // Advance past expiry.
    env.ledger().set_timestamp(1_700_000_500);

    // Repeatedly inspect expired invitations.
    let v1 = client.get_admin_invitation_status();
    assert_eq!(env.events().all().events().len(), 0);
    let v2 = client.get_admin_invitation_status();
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(v1, v2);
    assert_eq!(v1.state, RoleInvitationState::Expired);

    let r1 = client.get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer);
    assert_eq!(env.events().all().events().len(), 0);
    let r2 = client.get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer);
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(r1, r2);
    assert_eq!(r1.state, RoleInvitationState::Expired);

    // Prove underlying persistent keys were NOT deleted or mutated by the read calls.
    env.as_contract(&contract_id, || {
        let stored_pending: Option<Address> =
            env.storage().persistent().get(&DataKey::PendingAdmin);
        let stored_window: Option<(u64, u64)> =
            env.storage().persistent().get(&DataKey::AdminInviteExpiry);
        let stored_role: Option<RoleInvitationRecord> = env.storage().persistent().get(
            &DataKey::RoleInvite(INVITE_ROLE_ISSUER, cand_issuer.clone()),
        );

        assert_eq!(stored_pending, Some(cand_admin.clone()));
        assert_eq!(stored_window, Some((1_700_000_000, 1_700_000_120)));
        assert!(stored_role.is_some());
    });

    // Write-side acceptance still rejects expired invitations fail-closed.
    let accept_err = client.try_accept_admin(&cand_admin);
    assert_eq!(
        accept_err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::AlreadyExpired as u32
        )))
    );

    // Explicit admin cleanup transitions state back to Nonexistent.
    client.clear_role_invitation(&admin, &INVITE_ROLE_ISSUER, &cand_issuer);
    client.cancel_admin_transfer(&admin);
    assert_eq!(
        client.get_admin_invitation_status().state,
        RoleInvitationState::Nonexistent
    );
    assert_eq!(
        client
            .get_role_invitation_status(&INVITE_ROLE_ISSUER, &cand_issuer)
            .state,
        RoleInvitationState::Nonexistent
    );
}

#[test]
fn invalid_invitation_ttl_bounds_revert() {
    let (env, _contract_id, client, admin) = setup();
    let candidate = Address::generate(&env);

    let zero_err = client.try_propose_admin_expiring(&admin, &candidate, &0);
    assert_eq!(
        zero_err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInvitationDuration as u32
        )))
    );

    let over_err = client.try_invite_role_candidate(
        &admin,
        &INVITE_ROLE_ISSUER,
        &candidate,
        &(MAX_ROLE_INVITATION_TTL_SECS + 1),
    );
    assert_eq!(
        over_err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInvitationDuration as u32
        )))
    );
}
