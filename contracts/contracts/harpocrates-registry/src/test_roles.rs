//! Strict admin/issuer role separation and storage migration regression tests.
//!
//! These fixtures intentionally use synthetic hashes and addresses only. No
//! media, credentials, witness values, proof bytes, or private keys are present.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, BytesN, Env, IntoVal, Symbol,
};

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

const MAX_CPU_ROLE_CONFLICT: u64 = 2_000_000;
const MAX_MEM_ROLE_CONFLICT: u64 = 2_000_000;

#[test]
fn fresh_registry_starts_at_role_separated_schema_v2() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    assert_eq!(client.get_schema_version(), SchemaVersion::V2 as u32);
    assert!(client.is_admin(&admin));
    assert!(!client.is_issuer(&admin));
}

#[test]
fn separate_issuer_can_register_a_tier_three_seal() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);

    client.add_issuer(&admin, &issuer, &b32(&env, 0xA1));

    assert!(!client.is_admin(&issuer));
    assert!(client.is_issuer(&issuer));
    let record = client.register_seal(
        &issuer,
        &b32(&env, 0x11),
        &b32(&env, 0x12),
        &b32(&env, 0x13),
    );
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer));
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn admin_cannot_be_granted_issuer_role() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &admin, &b32(&env, 0xA1));
}

#[test]
fn rejected_role_assignment_has_a_bounded_budget() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    env.cost_estimate().budget().reset_unlimited();

    let result = client.try_add_issuer(&admin, &admin, &b32(&env, 0xA1));
    assert!(result.is_err(), "expected RoleConflict for admin/issuer overlap");

    let budget = env.cost_estimate().budget();
    assert!(budget.cpu_instruction_cost() <= MAX_CPU_ROLE_CONFLICT);
    assert!(budget.memory_bytes_cost() <= MAX_MEM_ROLE_CONFLICT);
    assert!(!client.is_issuer(&admin));
    assert_eq!(env.events().all().len(), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn active_issuer_cannot_be_proposed_as_admin() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xA1));

    client.propose_admin(&admin, &issuer);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn issuer_cannot_manage_issuer_roles() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let other_issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xA1));

    client.add_issuer(&issuer, &other_issuer, &b32(&env, 0xA2));
}

#[test]
fn revoked_issuer_record_does_not_block_admin_transfer() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let next_admin = Address::generate(&env);
    client.add_issuer(&admin, &next_admin, &b32(&env, 0xA1));
    client.revoke_issuer(&admin, &next_admin);
    assert!(!client.is_issuer(&next_admin));

    client.propose_admin(&admin, &next_admin);
    client.accept_admin(&next_admin);

    assert!(client.is_admin(&next_admin));
    let historical_record = client.get_issuer(&next_admin).expect("record must remain");
    assert!(!historical_record.active);
}

#[test]
fn admin_transfer_preserves_disjoint_roles_and_allows_old_admin_becoming_issuer() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let next_admin = Address::generate(&env);

    client.propose_admin(&admin, &next_admin);
    client.accept_admin(&next_admin);

    assert!(!client.is_admin(&admin));
    assert!(client.is_admin(&next_admin));
    assert!(!client.is_issuer(&next_admin));

    client.add_issuer(&next_admin, &admin, &b32(&env, 0xA1));
    assert!(client.is_issuer(&admin));
    assert!(!client.is_admin(&admin));
}

fn install_legacy_conflict(
    env: &Env,
    contract_id: &Address,
    admin: &Address,
) -> (ProofRecord, BytesN<32>) {
    let video_hash = b32(env, 0x31);
    let metadata_hash = b32(env, 0x32);
    let proof_id = b32(env, 0x33);
    let legacy_proof = ProofRecord {
        video_hash: video_hash.clone(),
        metadata_hash,
        tier: TIER_PUBLIC_SEAL,
        status: STATUS_REGISTERED,
        created_at: 1_700_000_000,
        expires_at: 0,
        source: None,
        issuer: Some(admin.clone()),
        nullifier: None,
        batch_size: 0,
    };

    env.as_contract(contract_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
        env.storage().persistent().set(
            &DataKey::Issuer(admin.clone()),
            &IssuerRecord {
                metadata_hash: b32(env, 0xA1),
                active: true,
            },
        );
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &legacy_proof);
        env.storage()
            .persistent()
            .set(&DataKey::Video(video_hash), &proof_id);
    });

    (legacy_proof, proof_id)
}

#[test]
fn v2_migration_revokes_only_conflicting_authority_and_preserves_stored_evidence() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let (legacy_proof, proof_id) = install_legacy_conflict(&env, &contract_id, &admin);
    let _ = env.events().all();

    assert_eq!(client.get_schema_version(), SchemaVersion::V1 as u32);
    client.upgrade_storage(&admin);

    assert_eq!(client.get_schema_version(), SchemaVersion::V2 as u32);
    let issuer = client.get_issuer(&admin).expect("issuer metadata must remain");
    assert!(!issuer.active);
    assert_eq!(issuer.metadata_hash, b32(&env, 0xA1));
    assert_eq!(client.get_proof(&proof_id), Some(legacy_proof));
    assert!(!client.is_issuer(&admin));
    assert!(client.is_admin(&admin));

    // IssuerRevoked and SchemaUpgraded are emitted, with no media or proof data.
    let events = env.events().all();
    assert_eq!(events.len(), 2);
    let issuer_topic: Symbol = events[0]
        .1
        .get(0)
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    let revoke_topic: Symbol = events[0]
        .1
        .get(1)
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    assert_eq!(issuer_topic, Symbol::new(&env, "issuer"));
    assert_eq!(revoke_topic, Symbol::new(&env, "revoke"));
    let upgraded: SchemaUpgraded = events[1].2.clone().try_into_val(&env).unwrap();
    assert_eq!(upgraded.previous, SchemaVersion::V1 as u32);
    assert_eq!(upgraded.current, SchemaVersion::V2 as u32);

    // Migration is idempotent: no repeated revocation or schema event.
    client.upgrade_storage(&admin);
    assert_eq!(env.events().all().len(), 0);
}

#[test]
fn v2_migration_preserves_non_conflicting_issuer_authority() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xA1));
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
    });
    let _ = env.events().all();

    client.upgrade_storage(&admin);

    assert_eq!(client.get_schema_version(), SchemaVersion::V2 as u32);
    assert!(client.is_issuer(&issuer));
    assert_eq!(
        client.get_issuer(&issuer).unwrap().metadata_hash,
        b32(&env, 0xA1)
    );
    // Only SchemaUpgraded is emitted when no authority conflicts.
    let events = env.events().all();
    assert_eq!(events.len(), 1);
    let schema_topic: Symbol = events[0]
        .1
        .get(0)
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    let upgrade_topic: Symbol = events[0]
        .1
        .get(1)
        .unwrap()
        .try_into_val(&env)
        .unwrap();
    assert_eq!(schema_topic, Symbol::new(&env, "schema"));
    assert_eq!(upgrade_topic, Symbol::new(&env, "upgrade"));
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn legacy_admin_issuer_record_cannot_seal_before_migration_runs() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    install_legacy_conflict(&env, &contract_id, &admin);

    client.register_seal(
        &admin,
        &b32(&env, 0x41),
        &b32(&env, 0x42),
        &b32(&env, 0x43),
    );
}

// ---------------------------------------------------------------------------
// Issuer metadata update tests
// ---------------------------------------------------------------------------

#[test]
fn update_issuer_metadata_succeeds_and_emits_event_once() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let initial_hash = b32(&env, 0x11);
    let updated_hash = b32(&env, 0x22);

    client.add_issuer(&admin, &issuer, &initial_hash);
    let before = client.get_issuer(&issuer).unwrap();
    assert_eq!(before.metadata_hash, initial_hash);
    assert!(before.active);

    client.update_issuer_metadata(&admin, &issuer, &updated_hash);

    let after = client.get_issuer(&issuer).unwrap();
    assert_eq!(after.metadata_hash, updated_hash);
    assert!(after.active); // only metadata hash changes

    assert_eq!(event_test_utils::count_events(&env, &["issuer", "metadata"]), 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn update_issuer_metadata_fails_for_unknown_issuer() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let unknown = Address::generate(&env);

    client.update_issuer_metadata(&admin, &unknown, &b32(&env, 0x33));
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn update_issuer_metadata_fails_for_revoked_issuer() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);

    client.add_issuer(&admin, &issuer, &b32(&env, 0x11));
    client.revoke_issuer(&admin, &issuer);

    client.update_issuer_metadata(&admin, &issuer, &b32(&env, 0x33));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn update_issuer_metadata_fails_for_non_admin_caller() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.add_issuer(&admin, &issuer, &b32(&env, 0x11));

    client.update_issuer_metadata(&stranger, &issuer, &b32(&env, 0x33));
}

// ---------------------------------------------------------------------------
// Authority revision and conflicting role transition tests
// ---------------------------------------------------------------------------

#[test]
fn queued_compatible_role_transition_is_preserved() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate = Address::generate(&env);

    assert_eq!(client.get_role_revision(), 1);
    assert_eq!(client.get_authority_revision(), 1);

    // Initial proposal
    client.propose_admin(&admin, &candidate);
    assert_eq!(client.get_pending_admin(), Some(candidate.clone()));
    let initial_events_len = env.events().all().len();

    // Queuing a compatible transition (same nominee) must succeed and preserve the queued transition.
    client.propose_admin(&admin, &candidate);
    assert_eq!(client.get_pending_admin(), Some(candidate.clone()));
    assert_eq!(client.get_role_revision(), 1);
    // Preserved compatible transition does not re-emit redundant proposal events.
    assert_eq!(env.events().all().len(), initial_events_len);

    // Candidate accepts intent and completes the transition.
    client.accept_admin(&candidate);
    assert_eq!(client.get_admin(), Some(candidate.clone()));
    assert_eq!(client.get_pending_admin(), None);
    assert_eq!(client.get_role_revision(), 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn conflicting_role_transition_queued_for_same_revision_is_rejected() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);

    client.propose_admin(&admin, &candidate_a);
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));

    // Proposing candidate_b while candidate_a is already queued for the same authority revision must panic with RoleConflict (#90).
    client.propose_admin(&admin, &candidate_b);
}

#[test]
fn conflicting_transition_rejection_preserves_existing_pending_nominee() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);

    client.propose_admin(&admin, &candidate_a);
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));

    let res = client.try_propose_admin(&admin, &candidate_b);
    assert!(res.is_err(), "conflicting transition must fail");

    // The original nominee must be preserved and remain able to accept.
    assert_eq!(client.get_pending_admin(), Some(candidate_a.clone()));
    client.accept_admin(&candidate_a);
    assert_eq!(client.get_admin(), Some(candidate_a));
    assert_eq!(client.get_role_revision(), 2);
}

#[test]
fn cancelling_queued_transition_allows_new_proposal_at_same_revision() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);

    assert_eq!(client.get_role_revision(), 1);

    client.propose_admin(&admin, &candidate_a);
    assert_eq!(client.get_pending_admin(), Some(candidate_a));

    client.cancel_admin_transfer(&admin);
    assert_eq!(client.get_pending_admin(), None);

    // After cancellation, proposing candidate_b at the same revision succeeds.
    client.propose_admin(&admin, &candidate_b);
    assert_eq!(client.get_pending_admin(), Some(candidate_b.clone()));

    client.accept_admin(&candidate_b);
    assert_eq!(client.get_admin(), Some(candidate_b));
    assert_eq!(client.get_role_revision(), 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn accepting_intent_with_stale_expected_revision_is_rejected() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate = Address::generate(&env);

    client.propose_admin(&admin, &candidate);
    // Expected revision 2 does not match current revision 1 -> RoleConflict (#90).
    client.accept_admin_with_revision(&candidate, &2u32);
}

#[test]
#[should_panic(expected = "Error(Contract, #90)")]
fn propose_with_mismatched_revision_is_rejected() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate = Address::generate(&env);

    // Current revision is 1; expecting 999 must reject with RoleConflict (#90).
    client.propose_admin_with_revision(&admin, &candidate, &999u32);
}

#[test]
fn propose_and_accept_with_revision_advances_role_revision() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate = Address::generate(&env);

    assert_eq!(client.get_role_revision(), 1);
    client.propose_admin_with_revision(&admin, &candidate, &1u32);
    assert_eq!(client.get_pending_admin(), Some(candidate.clone()));

    client.accept_admin_with_revision(&candidate, &1u32);
    assert_eq!(client.get_admin(), Some(candidate.clone()));
    assert_eq!(client.get_role_revision(), 2);
    assert_eq!(client.get_authority_revision(), 2);
}

#[test]
fn rejected_conflicting_transition_has_bounded_budget() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let candidate_a = Address::generate(&env);
    let candidate_b = Address::generate(&env);

    client.propose_admin(&admin, &candidate_a);
    let events_before = env.events().all().len();

    env.cost_estimate().budget().reset_unlimited();
    let result = client.try_propose_admin(&admin, &candidate_b);
    assert!(result.is_err(), "expected RoleConflict for conflicting transition");

    let budget = env.cost_estimate().budget();
    assert!(budget.cpu_instruction_cost() <= MAX_CPU_ROLE_CONFLICT);
    assert!(budget.memory_bytes_cost() <= MAX_MEM_ROLE_CONFLICT);

    // No new events emitted and pending nominee remains candidate_a.
    assert_eq!(env.events().all().len(), events_before);
    assert_eq!(client.get_pending_admin(), Some(candidate_a));
}
