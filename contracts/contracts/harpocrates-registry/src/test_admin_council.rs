#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    vec, Address, BytesN, Env,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn advance_time(env: &Env, secs: u64) {
    env.ledger().set_timestamp(env.ledger().timestamp() + secs);
}

/// Set up a fresh registry with single admin.
fn setup_admin() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

/// Set up a registry with an active 2-of-3 council.
/// Returns (env, contract_id, admin, m1, m2, m3).
fn setup_council_2_of_3() -> (Env, Address, Address, Address, Address, Address) {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let m3 = Address::generate(&env);

    let members = vec![&env, m1.clone(), m2.clone(), m3.clone()];
    client.set_admin_council(&admin, &members, &2);

    // Advance time past the timelock min delay so the council becomes active
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    (env, contract_id, admin, m1, m2, m3)
}

// ---------------------------------------------------------------------------
// 1. Single admin behaviour unchanged without council
// ---------------------------------------------------------------------------

#[test]
fn test_no_behaviour_change_without_council() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // No council configured
    assert!(client.get_admin_council().is_none());
    assert!(client.get_pending_admin_council().is_none());

    // Single admin can perform critical actions directly
    let root = b32(&env, 0xAA);
    client.set_revocation_root(&admin, &root);
    assert_eq!(client.get_revocation_root().unwrap(), root);

    // Storage upgrade works directly
    client.upgrade_storage(&admin);
    assert_eq!(client.get_schema_version(), SchemaVersion::V2 as u32);

    // Verifier set works directly
    let verifier = Address::generate(&env);
    client.set_verifier(&admin, &verifier);
    assert_eq!(client.get_verifier().unwrap(), verifier);

    // Issuer addition and revocation works directly
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0x11));
    assert!(client.get_issuer(&issuer).unwrap().active);
    client.revoke_issuer(&admin, &issuer);
    assert!(!client.get_issuer(&issuer).unwrap().active);
}

// ---------------------------------------------------------------------------
// 2. Timelock delay on council configuration & cancellation
// ---------------------------------------------------------------------------

#[test]
fn test_set_admin_council_timelock_delay() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let members = vec![&env, m1.clone(), m2.clone()];

    client.set_admin_council(&admin, &members, &2);

    // Immediately after call: council is pending, NOT yet active
    assert!(client.get_admin_council().is_none());
    let pending = client.get_pending_admin_council().unwrap();
    assert_eq!(pending.threshold, 2);
    assert_eq!(pending.members.len(), 2);

    // Single admin can still act because council is not active yet
    let root1 = b32(&env, 0x10);
    client.set_revocation_root(&admin, &root1);
    assert_eq!(client.get_revocation_root().unwrap(), root1);

    // Advance time past the timelock delay
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Now council is active
    assert!(client.get_pending_admin_council().is_none());
    let active = client.get_admin_council().unwrap();
    assert_eq!(active.threshold, 2);

    // Single admin can NO LONGER act directly (panics with InsufficientApprovals = 89)
    let root2 = b32(&env, 0x20);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_revocation_root(&admin, &root2);
    }));
    assert!(res.is_err(), "Single admin should be blocked once council is active");
}

#[test]
fn test_cancel_pending_admin_council() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let members = vec![&env, m1.clone(), m2.clone()];

    client.set_admin_council(&admin, &members, &2);
    assert!(client.get_pending_admin_council().is_some());

    // Cancel before timelock elapses
    client.cancel_pending_admin_council(&admin);
    assert!(client.get_pending_admin_council().is_none());

    // Advance time past timelock
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Council remains inactive
    assert!(client.get_admin_council().is_none());

    // Single admin can still act
    let root = b32(&env, 0x30);
    client.set_revocation_root(&admin, &root);
    assert_eq!(client.get_revocation_root().unwrap(), root);
}

#[test]
#[should_panic(expected = "Error(Contract, #89)")]
fn test_active_council_cannot_be_overwritten_by_single_admin() {
    let (env, contract_id, admin, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Attempting to overwrite active council directly without multi-party approval panics with InsufficientApprovals
    let new_members = vec![&env, m1.clone(), m2.clone()];
    client.set_admin_council(&admin, &new_members, &1);
}

// ---------------------------------------------------------------------------
// 3. Threshold enforcement (2-of-3 and 3-of-3)
// ---------------------------------------------------------------------------

#[test]
fn test_threshold_enforcement_2_of_3() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let target = Address::generate(&env);
    let payload = b32(&env, 0x55);

    // m1 proposes setting revocation root (action 4)
    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &target,
        &payload,
    );
    assert_eq!(proposal_id, 1);

    // m1 approves (1 approval out of 2 needed)
    let threshold_reached = client.approve_council_proposal(&m1, &proposal_id);
    assert!(!threshold_reached);

    // Attempt to execute with only 1 approval -> fails with InsufficientApprovals (#89)
    let caller = Address::generate(&env);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_council_proposal(&caller, &proposal_id);
    }));
    assert!(res.is_err(), "execution before threshold must fail");

    // m2 approves (2 approvals out of 2 needed)
    let threshold_reached2 = client.approve_council_proposal(&m2, &proposal_id);
    assert!(threshold_reached2);

    // Execute proposal -> succeeds!
    client.execute_council_proposal(&caller, &proposal_id);

    // Verify side effect: revocation root was updated
    assert_eq!(client.get_revocation_root().unwrap(), payload);

    // Verify proposal status
    let prop = client.get_council_proposal(&proposal_id).unwrap();
    assert!(prop.executed);

    // Second execution must fail
    let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_council_proposal(&caller, &proposal_id);
    }));
    assert!(res2.is_err(), "already executed proposal cannot be executed again");
}

#[test]
fn test_threshold_enforcement_3_of_3() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let m3 = Address::generate(&env);

    client.set_admin_council(&admin, &vec![&env, m1.clone(), m2.clone(), m3.clone()], &3);
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Setup an issuer
    let issuer = Address::generate(&env);
    // Issuer addition is done before council is locked or via single-admin before council
    // Here we can test revoking an issuer (action 2)
    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::RevokeIssuer as u32),
        &issuer,
        &b32(&env, 0),
    );

    client.approve_council_proposal(&m1, &proposal_id);
    client.approve_council_proposal(&m2, &proposal_id);

    // 2 of 3 is not enough
    let caller = Address::generate(&env);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_council_proposal(&caller, &proposal_id);
    }));
    assert!(res.is_err(), "2-of-3 approvals must fail when threshold is 3");

    // 3rd approval
    client.approve_council_proposal(&m3, &proposal_id);
    client.execute_council_proposal(&caller, &proposal_id);

    let prop = client.get_council_proposal(&proposal_id).unwrap();
    assert!(prop.executed);
}

#[test]
fn test_upgrade_storage_via_council() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::UpgradeStorage as u32),
        &m1,
        &b32(&env, 0),
    );

    client.approve_council_proposal(&m1, &proposal_id);
    client.approve_council_proposal(&m2, &proposal_id);

    let caller = Address::generate(&env);
    client.execute_council_proposal(&caller, &proposal_id);

    assert_eq!(client.get_schema_version(), SchemaVersion::V2 as u32);
}

#[test]
fn test_set_verifier_via_council() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let new_verifier = Address::generate(&env);
    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetVerifier as u32),
        &new_verifier,
        &b32(&env, 0),
    );

    client.approve_council_proposal(&m1, &proposal_id);
    client.approve_council_proposal(&m2, &proposal_id);

    let caller = Address::generate(&env);
    client.execute_council_proposal(&caller, &proposal_id);

    assert_eq!(client.get_verifier().unwrap(), new_verifier);
}

// ---------------------------------------------------------------------------
// 4. Duplicate-signer and non-member rejection
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_duplicate_approval_rejected() {
    let (env, contract_id, _, m1, _, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0),
    );

    client.approve_council_proposal(&m1, &proposal_id);
    // Duplicate approval by same member must panic
    client.approve_council_proposal(&m1, &proposal_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_duplicate_members_in_council_setup_rejected() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let m1 = Address::generate(&env);
    // m1 repeated twice
    let members = vec![&env, m1.clone(), m1.clone()];
    client.set_admin_council(&admin, &members, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_non_member_cannot_propose() {
    let (env, contract_id, _, _, _, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let outsider = Address::generate(&env);
    client.propose_council_action(
        &outsider,
        &(CouncilAction::SetRevocationRoot as u32),
        &outsider,
        &b32(&env, 0),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_non_member_cannot_approve() {
    let (env, contract_id, _, m1, _, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0),
    );

    let outsider = Address::generate(&env);
    client.approve_council_proposal(&outsider, &proposal_id);
}

// ---------------------------------------------------------------------------
// 5. Proposal expiry
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #17)")]
fn test_approve_expired_proposal_fails() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0),
    );

    // Advance time past proposal TTL (24h default)
    advance_time(&env, DEFAULT_APPROVAL_TTL_SECS + 1);

    // Attempting to approve an expired proposal panics with AlreadyExpired (#17)
    client.approve_council_proposal(&m2, &proposal_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #17)")]
fn test_execute_expired_proposal_fails() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0),
    );

    client.approve_council_proposal(&m1, &proposal_id);
    client.approve_council_proposal(&m2, &proposal_id);

    // Advance time past proposal TTL
    advance_time(&env, DEFAULT_APPROVAL_TTL_SECS + 1);

    // Attempting to execute an expired proposal panics with AlreadyExpired (#17)
    let caller = Address::generate(&env);
    client.execute_council_proposal(&caller, &proposal_id);
}

// ---------------------------------------------------------------------------
// 6. Interaction with timelock: single admin cannot bypass active council
// ---------------------------------------------------------------------------

#[test]
fn test_timelock_single_admin_bypass_blocked_when_council_active() {
    let (env, contract_id, admin) = setup_admin();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Propose a timelocked SetVerifier action as single admin before council is active
    let target_verifier = Address::generate(&env);
    let proposal_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::SetVerifier as u32),
        &target_verifier,
        &b32(&env, 0),
    );

    // Now configure council and advance time to make it active
    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    client.set_admin_council(&admin, &vec![&env, m1.clone(), m2.clone()], &2);
    advance_time(&env, DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);

    // Verify council is active
    assert!(client.get_admin_council().is_some());

    // Single admin cannot emergency execute the timelocked verifier proposal without council
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.emergency_execute_timelock(&admin, &proposal_id);
    }));
    assert!(res.is_err(), "emergency execute must be blocked when council is active");

    // Normal execution of timelocked verifier proposal is also blocked
    let caller = Address::generate(&env);
    let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_timelocked_proposal(&caller, &proposal_id);
    }));
    assert!(res2.is_err(), "timelocked execute must be blocked when council is active");
}

// ---------------------------------------------------------------------------
// 7. Event emissions
// ---------------------------------------------------------------------------

#[test]
fn test_events_for_council_lifecycle() {
    let (env, contract_id, _, m1, m2, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Propose
    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0x99),
    );
    assert!(event_test_utils::has_event(&env, &["council", "propose"]));

    // Approve
    client.approve_council_proposal(&m1, &proposal_id);
    assert!(event_test_utils::has_event(&env, &["council", "approve"]));

    client.approve_council_proposal(&m2, &proposal_id);
    assert!(event_test_utils::has_event(&env, &["council", "approve"]));

    // Execute
    let caller = Address::generate(&env);
    client.execute_council_proposal(&caller, &proposal_id);
    assert!(event_test_utils::has_event(&env, &["council", "exec"]));
}

// ---------------------------------------------------------------------------
// 8. Proposal cancellation
// ---------------------------------------------------------------------------

#[test]
fn test_cancel_council_proposal() {
    let (env, contract_id, _, m1, _, _) = setup_council_2_of_3();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let proposal_id = client.propose_council_action(
        &m1,
        &(CouncilAction::SetRevocationRoot as u32),
        &m1,
        &b32(&env, 0x88),
    );

    client.cancel_council_proposal(&m1, &proposal_id);
    assert!(event_test_utils::has_event(&env, &["council", "cancel"]));

    let prop = client.get_council_proposal(&proposal_id).unwrap();
    assert!(prop.cancelled);

    // Attempt to approve cancelled proposal
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.approve_council_proposal(&m1, &proposal_id);
    }));
    assert!(res.is_err());
}
