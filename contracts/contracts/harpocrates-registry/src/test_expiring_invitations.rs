#![cfg(test)]

use crate::{
    HarpocratesRegistry, HarpocratesRegistryClient, RegistryError, INVITE_ROLE_ADMIN,
    INVITE_ROLE_GUARDIAN, INVITE_ROLE_ISSUER, INVITE_ROLE_SEAL_SIGNER, MAX_INVITATION_TTL_SECS,
    PAUSE_DOMAIN_TIER3_REGISTRATION,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env,
};

fn setup() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, client, admin)
}

#[test]
fn retains_prior_role_until_accepted_and_transitions_before_deadline() {
    let (env, client, admin) = setup();
    let old_guardian = Address::generate(&env);
    let new_guardian = Address::generate(&env);
    let cand_issuer = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let zero_meta = BytesN::from_array(&env, &[0u8; 32]);
    let issuer_meta = BytesN::from_array(&env, &[0x44; 32]);

    // Configure an existing guardian and seal policy.
    client.set_guardian(&admin, &old_guardian);
    let pol_ver = client.create_seal_policy(&admin, &1, &2, &3600, &0);

    // 1. Invite new guardian, new issuer, and new admin.
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_GUARDIAN,
        &new_guardian,
        &zero_meta,
        &0,
        &600,
    );
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_ISSUER,
        &cand_issuer,
        &issuer_meta,
        &0,
        &600,
    );
    client.create_approval_invitation(&admin, &INVITE_ROLE_ADMIN, &new_admin, &zero_meta, &0, &600);

    // Prior role assignments remain authoritative while invitations are pending!
    assert_eq!(client.get_admin(), Some(admin.clone()));
    assert_eq!(client.get_guardian(), Some(old_guardian.clone()));
    assert!(!client.is_issuer(&cand_issuer));

    // Old guardian still exercises pause authority; invited guardian cannot yet pause.
    assert_eq!(
        client.try_pause(&new_guardian, &PAUSE_DOMAIN_TIER3_REGISTRATION, &60),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::Unauthorized as u32
        )))
    );
    client.pause(&old_guardian, &PAUSE_DOMAIN_TIER3_REGISTRATION, &60);
    client.unpause(&admin, &PAUSE_DOMAIN_TIER3_REGISTRATION);

    // Invited issuer cannot register seals before accepting.
    let proof_id = BytesN::from_array(&env, &[0xAA; 32]);
    let video_hash = BytesN::from_array(&env, &[0xBB; 32]);
    assert_eq!(
        client.try_register_seal(&cand_issuer, &proof_id, &video_hash, &issuer_meta),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::UnknownIssuer as u32
        )))
    );

    // 2. Accept issuer invitation at `expires_at - 1` -> becomes active issuer.
    env.ledger().set_timestamp(1_700_000_599);
    client.accept_approval_invitation(&cand_issuer, &INVITE_ROLE_ISSUER);
    assert!(client.is_issuer(&cand_issuer));
    assert_eq!(
        client.get_approval_invitation(&INVITE_ROLE_ISSUER, &cand_issuer),
        None
    );

    // Now invite `cand_issuer` into the seal policy signer set and verify signer list
    // stays empty until accepted.
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_SEAL_SIGNER,
        &cand_issuer,
        &zero_meta,
        &pol_ver,
        &300,
    );
    assert_eq!(
        client
            .get_seal_policy_by_version(&pol_ver)
            .unwrap()
            .signers
            .len(),
        0
    );
    client.accept_approval_invitation(&cand_issuer, &INVITE_ROLE_SEAL_SIGNER);
    assert_eq!(
        client
            .get_seal_policy_by_version(&pol_ver)
            .unwrap()
            .signers
            .len(),
        1
    );

    // 3. Accept guardian & admin invitations before deadline (`1_700_000_599 < 1_700_000_600`).
    client.accept_approval_invitation(&new_guardian, &INVITE_ROLE_GUARDIAN);
    assert_eq!(client.get_guardian(), Some(new_guardian.clone()));

    client.accept_approval_invitation(&new_admin, &INVITE_ROLE_ADMIN);
    assert_eq!(client.get_admin(), Some(new_admin));
}

#[test]
fn expired_cancelled_and_invalid_invitations_fail_closed_preserving_prior_roles() {
    let (env, client, admin) = setup();
    let old_guardian = Address::generate(&env);
    let cand_guardian = Address::generate(&env);
    let cand_admin = Address::generate(&env);
    let cand_issuer = Address::generate(&env);
    let zero_meta = BytesN::from_array(&env, &[0u8; 32]);

    client.set_guardian(&admin, &old_guardian);

    // Invalid TTL bounds (`0` and `> MAX_INVITATION_TTL_SECS`) revert with InvalidInvitationDuration.
    assert_eq!(
        client.try_create_approval_invitation(
            &admin,
            &INVITE_ROLE_ADMIN,
            &cand_admin,
            &zero_meta,
            &0,
            &0,
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInvitationDuration as u32
        )))
    );
    assert_eq!(
        client.try_create_approval_invitation(
            &admin,
            &INVITE_ROLE_ADMIN,
            &cand_admin,
            &zero_meta,
            &0,
            &(MAX_INVITATION_TTL_SECS + 1),
        ),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidInvitationDuration as u32
        )))
    );

    // Create 120-second invitations for admin, guardian, and issuer.
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_ADMIN,
        &cand_admin,
        &zero_meta,
        &0,
        &120,
    );
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_GUARDIAN,
        &cand_guardian,
        &zero_meta,
        &0,
        &120,
    );
    client.create_approval_invitation(
        &admin,
        &INVITE_ROLE_ISSUER,
        &cand_issuer,
        &zero_meta,
        &0,
        &120,
    );

    // Cancel the issuer invitation before expiry -> acceptance reverts with InvitationNotFound.
    client.cancel_approval_invitation(&admin, &INVITE_ROLE_ISSUER, &cand_issuer);
    assert_eq!(
        client.try_accept_approval_invitation(&cand_issuer, &INVITE_ROLE_ISSUER),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvitationNotFound as u32
        )))
    );

    // Advance to exact `expires_at` (`1_700_000_120`): acceptance MUST fail closed with InvitationExpired
    // and retain both `admin` and `old_guardian`.
    env.ledger().set_timestamp(1_700_000_120);
    assert_eq!(
        client.try_accept_approval_invitation(&cand_admin, &INVITE_ROLE_ADMIN),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvitationExpired as u32
        )))
    );
    assert_eq!(
        client.try_accept_approval_invitation(&cand_guardian, &INVITE_ROLE_GUARDIAN),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvitationExpired as u32
        )))
    );

    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(client.get_guardian(), Some(old_guardian));
}
