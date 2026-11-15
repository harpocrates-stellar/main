#![cfg(test)]

use crate::{
    event_test_utils::{event_u32_field, symbol_topics},
    ApprovalCancelReason, HarpocratesRegistry, HarpocratesRegistryClient, ProposalAction,
    RegistryError, MAX_APPROVAL_CANCEL_REASON,
};
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    xdr::{ContractEventBody, ScVal},
    Address, BytesN, Env, Vec,
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

fn topic_u32(event: &soroban_sdk::xdr::ContractEvent, idx: usize) -> Option<u32> {
    let ContractEventBody::V0(v0) = &event.body;
    match v0.topics.get(idx)? {
        ScVal::U32(v) => Some(*v),
        _ => None,
    }
}

#[test]
fn emits_bounded_reason_code_and_preserves_stable_approval_identity() {
    let (env, client, admin) = setup();
    let pending_admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    let issuer_1 = Address::generate(&env);
    let issuer_2 = Address::generate(&env);
    let zero = BytesN::from_array(&env, &[0u8; 32]);
    let meta = BytesN::from_array(&env, &[0x33; 32]);

    // 1. Admin transfer cancellation with explicit reason preserves `pending_admin` topic + `reason_code`.
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_with_reason(&admin, &(ApprovalCancelReason::OperatorWithdrawn as u32));
    let admin_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(symbol_topics(&admin_ev), std::vec!["admin", "cancel"]);
    assert_eq!(
        event_u32_field(&admin_ev, "reason_code"),
        Some(ApprovalCancelReason::OperatorWithdrawn as u32)
    );

    // Legacy `cancel_admin_transfer` stays compatible and emits `Unspecified (0)`.
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_transfer(&admin);
    let legacy_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(
        event_u32_field(&legacy_ev, "reason_code"),
        Some(ApprovalCancelReason::Unspecified as u32)
    );

    // 2. Timelock proposal cancellation preserves stable `proposal_id` topic + `reason_code`.
    let tl_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &verifier,
        &zero,
    );
    client.cancel_timelock_with_reason(&admin, &tl_id, &(ApprovalCancelReason::Superseded as u32));
    let tl_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(symbol_topics(&tl_ev), std::vec!["timelock", "cancel"]);
    assert_eq!(topic_u32(&tl_ev, 2), Some(tl_id));
    assert_eq!(
        event_u32_field(&tl_ev, "reason_code"),
        Some(ApprovalCancelReason::Superseded as u32)
    );

    // 3. Threshold seal approval withdrawal + seal policy cancellation preserve `(proof_id, signer)` and `version`.
    client.add_issuer(&admin, &issuer_1, &meta);
    client.add_issuer(&admin, &issuer_2, &meta);
    let pol_ver = client.create_seal_policy(&admin, &2, &2, &3600, &0);
    client.add_seal_policy_signer(&admin, &pol_ver, &issuer_1);
    client.add_seal_policy_signer(&admin, &pol_ver, &issuer_2);

    let proof_id = BytesN::from_array(&env, &[0x77; 32]);
    let video_hash = BytesN::from_array(&env, &[0x88; 32]);
    assert!(!client.approve_seal(&issuer_1, &proof_id, &video_hash, &meta));

    client.cancel_seal_approval(
        &issuer_1,
        &proof_id,
        &(ApprovalCancelReason::KeyCompromised as u32),
    );
    let seal_app_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(symbol_topics(&seal_app_ev), std::vec!["seal", "cancel"]);
    assert_eq!(
        event_u32_field(&seal_app_ev, "policy_version"),
        Some(pol_ver)
    );
    assert_eq!(
        event_u32_field(&seal_app_ev, "reason_code"),
        Some(ApprovalCancelReason::KeyCompromised as u32)
    );
    assert_eq!(client.get_seal_approval(&proof_id, &issuer_1), None);

    client.cancel_seal_pol_with_reason(
        &admin,
        &pol_ver,
        &(ApprovalCancelReason::PolicyChanged as u32),
    );
    let pol_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(symbol_topics(&pol_ev), std::vec!["seal_pol", "cancel"]);
    assert_eq!(topic_u32(&pol_ev, 2), Some(pol_ver));
    assert_eq!(
        event_u32_field(&pol_ev, "reason_code"),
        Some(ApprovalCancelReason::PolicyChanged as u32)
    );

    // 4. Council proposal cancellation preserves stable `proposal_id` topic + `reason_code`.
    let member_1 = Address::generate(&env);
    let member_2 = Address::generate(&env);
    let mut members = Vec::new(&env);
    members.push_back(member_1.clone());
    members.push_back(member_2);
    client.set_admin_council(&admin, &members, &2);
    let min_delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(1_700_000_000 + min_delay + 1);

    let cp_id = client.propose_council_action(&member_1, &1, &verifier, &zero);
    client.cancel_council_with_reason(
        &member_1,
        &cp_id,
        &(ApprovalCancelReason::QuorumRestructured as u32),
    );
    let cp_ev = env.events().all().events().first().cloned().unwrap();
    assert_eq!(symbol_topics(&cp_ev), std::vec!["council", "cancel"]);
    assert_eq!(topic_u32(&cp_ev, 2), Some(cp_id));
    assert_eq!(
        event_u32_field(&cp_ev, "reason_code"),
        Some(ApprovalCancelReason::QuorumRestructured as u32)
    );
}

#[test]
fn rejects_out_of_range_or_zero_explicit_cancellation_reason_codes() {
    let (env, client, admin) = setup();
    let pending_admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    let zero = BytesN::from_array(&env, &[0u8; 32]);

    client.propose_admin(&admin, &pending_admin);
    let tl_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &verifier,
        &zero,
    );

    // Explicit reason entry points reject `0` (`Unspecified`) and `> MAX_APPROVAL_CANCEL_REASON`
    // without mutating pending state or emitting events.
    assert_eq!(
        client.try_cancel_admin_with_reason(&admin, &0),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidReasonCode as u32
        )))
    );
    assert_eq!(
        client.try_cancel_admin_with_reason(&admin, &(MAX_APPROVAL_CANCEL_REASON + 1)),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidReasonCode as u32
        )))
    );
    assert_eq!(
        client.try_cancel_timelock_with_reason(&admin, &tl_id, &99),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidReasonCode as u32
        )))
    );

    // Pending approvals remain intact after rejected reason codes.
    assert_eq!(client.get_pending_admin(), Some(pending_admin));
    assert!(!client.get_timelock_proposal(&tl_id).unwrap().cancelled);
}
