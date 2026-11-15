#![cfg(test)]

use crate::{
    HarpocratesRegistry, HarpocratesRegistryClient, InstitutionalRole, RegistryError,
    CAP_ACCEPT_ADMIN, CAP_ADD_ISSUER, CAP_APPROVE_SEAL, CAP_GRANT_DELEGATION, CAP_MANAGE_ROOTS,
    CAP_PAUSE_REGISTRY, CAP_PROPOSE_TIMELOCK, CAP_REGISTER_SEAL, CAP_REVOKE_ISSUER,
    CAP_SET_REVOCATION_ROOT, CAP_SET_VERIFIER, CAP_UNPAUSE_REGISTRY, CAP_UPGRADE_STORAGE,
    CAP_VOTE_COUNCIL, MAX_GUARDIAN_PAUSE_DURATION_SECS, MAX_PAUSE_DURATION_SECS,
    PAUSE_DOMAIN_TIER3_REGISTRATION, ROLE_BIT_ACTIVE_ISSUER, ROLE_BIT_ADMIN,
    ROLE_BIT_COUNCIL_MEMBER, ROLE_BIT_GUARDIAN, ROLE_BIT_PENDING_ADMIN, ROLE_BIT_SEAL_SIGNER,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn setup() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    (env, client, admin)
}

#[test]
fn uninitialized_and_outsider_queries_report_zero_capabilities() {
    let (env, client, admin) = setup();
    let outsider = Address::generate(&env);

    // Before `init`, every role and actor reports zero capabilities.
    let pre_admin = client.get_role_capabilities(&InstitutionalRole::Admin);
    assert_eq!(pre_admin.role_mask, 0);
    assert_eq!(pre_admin.capability_mask, 0);
    assert_eq!(pre_admin.max_pause_secs, 0);

    client.init(&admin);

    let out_caps = client.get_actor_capabilities(&outsider);
    assert_eq!(out_caps.role_mask, 0);
    assert_eq!(out_caps.capability_mask, 0);
    assert_eq!(out_caps.council_gated_mask, 0);
    assert_eq!(out_caps.max_pause_secs, 0);

    // Write-side enforcement rejects the outsider with `Unauthorized`.
    assert_eq!(
        client.try_set_guardian(&outsider, &outsider),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::Unauthorized as u32
        )))
    );
}

#[test]
fn introspects_live_role_capabilities_and_preserves_write_side_enforcement() {
    let (env, client, admin) = setup();
    client.init(&admin);

    let pending_admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let guardian = Address::generate(&env);
    let council_member = Address::generate(&env);
    let verifier = Address::generate(&env);
    let meta = BytesN::from_array(&env, &[0x55; 32]);

    // 1. Single-admin mode: Admin directly holds all admin + council-gated bits.
    let admin_caps = client.get_actor_capabilities(&admin);
    assert_eq!(admin_caps.role_mask, ROLE_BIT_ADMIN);
    assert_ne!(admin_caps.capability_mask & CAP_ADD_ISSUER, 0);
    assert_ne!(admin_caps.capability_mask & CAP_REVOKE_ISSUER, 0);
    assert_ne!(admin_caps.capability_mask & CAP_SET_VERIFIER, 0);
    assert_ne!(admin_caps.capability_mask & CAP_SET_REVOCATION_ROOT, 0);
    assert_ne!(admin_caps.capability_mask & CAP_UPGRADE_STORAGE, 0);
    assert_ne!(admin_caps.capability_mask & CAP_MANAGE_ROOTS, 0);
    assert_ne!(admin_caps.capability_mask & CAP_PROPOSE_TIMELOCK, 0);
    assert_ne!(admin_caps.capability_mask & CAP_PAUSE_REGISTRY, 0);
    assert_ne!(admin_caps.capability_mask & CAP_UNPAUSE_REGISTRY, 0);
    assert_eq!(admin_caps.council_gated_mask, 0);
    assert_eq!(admin_caps.max_pause_secs, MAX_PAUSE_DURATION_SECS);

    // 2. Configure PendingAdmin, ActiveIssuer + SealPolicySigner, and Guardian.
    client.propose_admin(&admin, &pending_admin);
    client.add_issuer(&admin, &issuer, &meta);
    let pol_ver = client.create_seal_policy(&admin, &1, &2, &3600, &0);
    client.add_seal_policy_signer(&admin, &pol_ver, &issuer);
    client.set_guardian(&admin, &guardian);

    let pending_caps = client.get_actor_capabilities(&pending_admin);
    assert_eq!(pending_caps.role_mask, ROLE_BIT_PENDING_ADMIN);
    assert_eq!(pending_caps.capability_mask, CAP_ACCEPT_ADMIN);

    let issuer_caps = client.get_actor_capabilities(&issuer);
    assert_eq!(
        issuer_caps.role_mask,
        ROLE_BIT_ACTIVE_ISSUER | ROLE_BIT_SEAL_SIGNER
    );
    assert_eq!(
        issuer_caps.capability_mask,
        CAP_REGISTER_SEAL | CAP_GRANT_DELEGATION | CAP_APPROVE_SEAL
    );

    let guardian_caps = client.get_actor_capabilities(&guardian);
    assert_eq!(guardian_caps.role_mask, ROLE_BIT_GUARDIAN);
    assert_eq!(guardian_caps.capability_mask, CAP_PAUSE_REGISTRY);
    assert_eq!(
        guardian_caps.max_pause_secs,
        MAX_GUARDIAN_PAUSE_DURATION_SECS
    );

    // Write-side parity check for Guardian: can pause within cap, CANNOT unpause or exceed cap!
    assert_eq!(
        client.try_pause(
            &guardian,
            &PAUSE_DOMAIN_TIER3_REGISTRATION,
            &(MAX_GUARDIAN_PAUSE_DURATION_SECS + 1),
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidPauseDuration as u32
        )))
    );
    client.pause(&guardian, &PAUSE_DOMAIN_TIER3_REGISTRATION, &120);
    assert_eq!(
        client.try_unpause(&guardian, &PAUSE_DOMAIN_TIER3_REGISTRATION),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::Unauthorized as u32
        )))
    );

    // 3. While Tier 3 is paused, introspection drops `CAP_REGISTER_SEAL` and `CAP_APPROVE_SEAL`
    // while retaining `CAP_GRANT_DELEGATION`, matching write-side `Paused` enforcement!
    let paused_issuer_caps = client.get_actor_capabilities(&issuer);
    assert_eq!(
        paused_issuer_caps.paused_domains,
        PAUSE_DOMAIN_TIER3_REGISTRATION
    );
    assert_eq!(paused_issuer_caps.capability_mask, CAP_GRANT_DELEGATION);

    let proof_id = BytesN::from_array(&env, &[0x91; 32]);
    let video_hash = BytesN::from_array(&env, &[0x92; 32]);
    assert_eq!(
        client.try_register_seal(&issuer, &proof_id, &video_hash, &meta),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::Paused as u32
        )))
    );

    client.unpause(&admin, &PAUSE_DOMAIN_TIER3_REGISTRATION);

    // 4. Activate an AdminCouncil: council-gated bits move from `Admin.capability_mask`
    // into `Admin.council_gated_mask`, and `CouncilMember` gains `CAP_VOTE_COUNCIL`.
    let mut members = Vec::new(&env);
    members.push_back(council_member.clone());
    client.set_admin_council(&admin, &members, &1);

    // During timelock delay, council is still pending -> `CouncilMember` has 0 vote cap.
    assert_eq!(
        client
            .get_role_capabilities(&InstitutionalRole::CouncilMember)
            .capability_mask,
        0
    );

    let min_delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(1_700_000_000 + min_delay + 1);

    let gated_admin = client.get_actor_capabilities(&admin);
    assert_eq!(gated_admin.capability_mask & CAP_SET_VERIFIER, 0);
    assert_eq!(gated_admin.capability_mask & CAP_REVOKE_ISSUER, 0);
    assert_eq!(
        gated_admin.council_gated_mask,
        CAP_REVOKE_ISSUER | CAP_SET_VERIFIER | CAP_SET_REVOCATION_ROOT | CAP_UPGRADE_STORAGE
    );

    let member_caps = client.get_actor_capabilities(&council_member);
    assert_eq!(member_caps.role_mask, ROLE_BIT_COUNCIL_MEMBER);
    assert_eq!(member_caps.capability_mask, CAP_VOTE_COUNCIL);

    // Write-side enforcement matches: direct single-admin `set_verifier` & `revoke_issuer`
    // revert with `InsufficientApprovals`.
    assert_eq!(
        client.try_set_verifier(&admin, &verifier),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InsufficientApprovals as u32
        )))
    );
    assert_eq!(
        client.try_revoke_issuer(&admin, &issuer),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InsufficientApprovals as u32
        )))
    );
}
