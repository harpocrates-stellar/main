//! Institutional role revocation readiness report tests (#1193).
//!
//! Uses synthetic addresses and hashes only — no real media, witness values,
//! credentials, or private keys are present.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

#[test]
fn report_identifies_active_and_expired_delegations_without_mutating_state() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let delegate_active = Address::generate(&env);
    let delegate_short = Address::generate(&env);
    let delegate_revoked = Address::generate(&env);

    client.add_issuer(&admin, &issuer, &b32(&env, 0x11));
    client.grant_delegation(
        &issuer,
        &delegate_active,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &3600,
    );
    client.grant_delegation(
        &issuer,
        &delegate_short,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &60,
    );
    client.grant_delegation(
        &issuer,
        &delegate_revoked,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &3600,
    );
    client.revoke_delegation(&issuer, &issuer, &delegate_revoked);

    // Advance ledger past delegate_short expiry while delegate_active stays live.
    env.ledger().set_timestamp(10_100);

    let report = client.get_role_revocation_report(&issuer);
    // Must emit zero events (pure read-only query).
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(report.subject, issuer);
    assert!(report.is_active_issuer);
    assert_eq!(report.active_delegation_count, 1);
    assert_eq!(report.expired_delegation_count, 1);
    assert_eq!(report.active_delegates.len(), 1);
    assert_eq!(
        report.active_delegates.get(0),
        Some(delegate_active.clone())
    );
    assert!(!report.ready_for_clean_revoke);

    // Read-only guarantee: raw expired DelegationRecord is still stored untouched,
    // and live delegation still works until actual revocation.
    assert!(client.get_delegation(&issuer, &delegate_short).is_some());
    assert!(client.is_delegation_active(
        &issuer,
        &delegate_active,
        &DELEGATION_SCOPE_REGISTER_SEAL
    ));

    // Once active delegation is revoked, issuer becomes ready for clean revoke.
    client.revoke_delegation(&issuer, &issuer, &delegate_active);
    let clean_report = client.get_role_revocation_report(&issuer);
    assert_eq!(clean_report.active_delegation_count, 0);
    assert_eq!(clean_report.expired_delegation_count, 1);
    assert!(clean_report.ready_for_clean_revoke);
}

#[test]
fn report_identifies_pending_seal_approvals_and_quorum_risk() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let signer1 = Address::generate(&env);
    let signer2 = Address::generate(&env);
    let signer3 = Address::generate(&env);

    client.add_issuer(&admin, &signer1, &b32(&env, 0x21));
    client.add_issuer(&admin, &signer2, &b32(&env, 0x22));
    client.add_issuer(&admin, &signer3, &b32(&env, 0x23));

    // 2-of-3 policy initially populated with only 2 signers => quorum at risk!
    let version = client.create_seal_policy(&admin, &2, &3, &600, &0);
    client.add_seal_policy_signer(&admin, &version, &signer1);
    client.add_seal_policy_signer(&admin, &version, &signer2);

    let proof_pending = b32(&env, 0x51);
    let video_pending = b32(&env, 0x52);
    let meta_pending = b32(&env, 0x53);

    let finalized = client.approve_seal(&signer1, &proof_pending, &video_pending, &meta_pending);
    assert!(!finalized);

    let r1 = client.get_role_revocation_report(&signer1);
    assert_eq!(env.events().all().events().len(), 0);
    assert!(r1.in_active_seal_policy);
    assert!(r1.seal_quorum_at_risk);
    assert_eq!(r1.pending_seal_approvals, 1);
    assert_eq!(
        r1.pending_seal_proof_ids.get(0),
        Some(proof_pending.clone())
    );
    assert!(!r1.ready_for_clean_revoke);

    // Adding a 3rd active signer removes quorum risk, though pending approval remains.
    client.add_seal_policy_signer(&admin, &version, &signer3);
    let r2 = client.get_role_revocation_report(&signer1);
    assert!(!r2.seal_quorum_at_risk);
    assert_eq!(r2.pending_seal_approvals, 1);
    assert!(!r2.ready_for_clean_revoke);

    // Once signer2 finalizes the threshold seal, signer1's approval is no longer pending.
    let done = client.approve_seal(&signer2, &proof_pending, &video_pending, &meta_pending);
    assert!(done);

    let r3 = client.get_role_revocation_report(&signer1);
    assert_eq!(r3.pending_seal_approvals, 0);
    assert_eq!(r3.pending_seal_proof_ids.len(), 0);
    assert!(r3.ready_for_clean_revoke);
}

#[test]
fn report_surfaces_council_approvals_timelock_targets_and_preserves_revocation_policy() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let member1 = Address::generate(&env);
    let member2 = Address::generate(&env);

    client.add_issuer(&admin, &issuer, &b32(&env, 0x31));

    // Queue a timelock RevokeIssuer (action = 2) targeting `issuer` before council activates.
    let _tl_id = client.propose_timelocked_action(&admin, &2, &issuer, &b32(&env, 0x00));
    let pre_council = client.get_role_revocation_report(&issuer);
    assert_eq!(pre_council.pending_timelock_targets, 1);
    assert!(!pre_council.requires_council_approval);

    // Activate a 2-of-2 AdminCouncil.
    let mut members = Vec::new(&env);
    members.push_back(member1.clone());
    members.push_back(member2.clone());
    client.set_admin_council(&admin, &members, &2);
    let delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(10_000 + delay + 1);

    let prop_id = client.propose_council_action(&member1, &2, &issuer, &b32(&env, 0x00));
    let reached = client.approve_council_proposal(&member1, &prop_id);
    assert!(!reached);

    let member_report = client.get_role_revocation_report(&member1);
    assert_eq!(env.events().all().events().len(), 0);
    assert!(member_report.in_admin_council);
    assert!(member_report.council_quorum_at_risk);
    assert!(member_report.requires_council_approval);
    assert_eq!(member_report.pending_council_approvals, 1);
    assert_eq!(member_report.pending_council_prop_ids.get(0), Some(prop_id));
    assert!(!member_report.ready_for_clean_revoke);

    let issuer_report = client.get_role_revocation_report(&issuer);
    assert!(issuer_report.requires_council_approval);

    // Approved revocation policy MUST remain enforced: unilateral admin revoke_issuer
    // reverts with InsufficientApprovals while council is active.
    let direct_revoke = client.try_revoke_issuer(&admin, &issuer);
    assert_eq!(
        direct_revoke,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InsufficientApprovals as u32
        )))
    );
    assert!(client.is_issuer(&issuer));

    // Completing council threshold approval & execution revokes the issuer cleanly.
    assert!(client.approve_council_proposal(&member2, &prop_id));
    client.execute_council_proposal(&member2, &prop_id);
    assert!(!client.is_issuer(&issuer));

    let post_exec = client.get_role_revocation_report(&member1);
    assert_eq!(post_exec.pending_council_approvals, 0);
}

#[test]
fn report_tracks_issuer_rotation_grace_guardian_and_pending_admin_flags() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let old_issuer = Address::generate(&env);
    let new_issuer = Address::generate(&env);
    let guardian = Address::generate(&env);
    let candidate_admin = Address::generate(&env);

    client.add_issuer(&admin, &old_issuer, &b32(&env, 0x41));
    client.add_issuer(&admin, &new_issuer, &b32(&env, 0x42));
    let grace_end = client.rotate_issuer(&admin, &old_issuer, &new_issuer, &300);

    let rot_report = client.get_role_revocation_report(&old_issuer);
    assert!(!rot_report.is_active_issuer);
    assert!(rot_report.has_rotation_grace);
    assert!(!rot_report.ready_for_clean_revoke);

    env.ledger().set_timestamp(grace_end);
    client.finalize_issuer_rotation(&old_issuer);
    let settled = client.get_role_revocation_report(&old_issuer);
    assert!(!settled.has_rotation_grace);
    assert!(settled.ready_for_clean_revoke);

    client.set_guardian(&admin, &guardian);
    client.propose_admin(&admin, &candidate_admin);

    let g_report = client.get_role_revocation_report(&guardian);
    assert!(g_report.is_guardian);
    assert!(g_report.ready_for_clean_revoke);

    let pa_report = client.get_role_revocation_report(&candidate_admin);
    assert!(pa_report.is_pending_admin);
    assert!(pa_report.ready_for_clean_revoke);
}
