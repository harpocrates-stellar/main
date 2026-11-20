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
#[should_panic(expected = "Error(Contract, #53)")]
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
#[should_panic(expected = "Error(Contract, #53)")]
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
#[should_panic(expected = "Error(Contract, #53)")]
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
// Institutional authority history tests
// ---------------------------------------------------------------------------

#[test]
fn initial_admin_records_authority_history() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    assert_eq!(client.get_authority_history_count(), 1);
    assert_eq!(client.get_approver_authority_history_count(&admin), 1);

    let entry = client.get_authority_history_at(&1).expect("entry must exist");
    assert_eq!(entry.reference, 1);
    assert_eq!(entry.approver, admin);
    assert_eq!(entry.role, ROLE_ADMIN);
    assert_eq!(entry.transition, TRANSITION_INITIALIZED);
    assert_eq!(entry.actor, Some(admin.clone()));
    assert_eq!(entry.metadata_hash, None);
    assert_eq!(entry.ledger_timestamp, env.ledger().timestamp());

    let page = client.get_institutional_authority_history(&0, &MAX_AUTHORITY_HISTORY_PAGE);
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries.get(0).unwrap(), entry);
    assert_eq!(page.next_offset, 1);
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.total, 1);

    let alias_page = client.get_authority_history(&0, &MAX_AUTHORITY_HISTORY_PAGE);
    assert_eq!(alias_page, page);

    let approver_page = client.get_approver_authority_history(&admin, &0, &MAX_AUTHORITY_HISTORY_PAGE);
    assert_eq!(approver_page.entries.len(), 1);
    assert_eq!(approver_page.entries.get(0).unwrap(), entry);
    assert_eq!(approver_page.total, 1);
    assert_eq!(approver_page.next_cursor, None);
}

#[test]
fn admin_transfer_lifecycle_records_authority_transitions() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let next_admin = Address::generate(&env);

    // Propose admin
    client.propose_admin(&admin, &next_admin);
    assert_eq!(client.get_authority_history_count(), 2);
    assert_eq!(client.get_approver_authority_history_count(&next_admin), 1);

    let prop_entry = client.get_authority_history_at(&2).unwrap();
    assert_eq!(prop_entry.reference, 2);
    assert_eq!(prop_entry.approver, next_admin);
    assert_eq!(prop_entry.role, ROLE_ADMIN);
    assert_eq!(prop_entry.transition, TRANSITION_PROPOSED);
    assert_eq!(prop_entry.actor, Some(admin.clone()));

    // Cancel proposal
    client.cancel_admin_transfer(&admin);
    assert_eq!(client.get_authority_history_count(), 3);
    assert_eq!(client.get_approver_authority_history_count(&next_admin), 2);

    let cancel_entry = client.get_authority_history_at(&3).unwrap();
    assert_eq!(cancel_entry.reference, 3);
    assert_eq!(cancel_entry.approver, next_admin);
    assert_eq!(cancel_entry.role, ROLE_ADMIN);
    assert_eq!(cancel_entry.transition, TRANSITION_CANCELLED);
    assert_eq!(cancel_entry.actor, Some(admin.clone()));

    // Propose again and accept
    client.propose_admin(&admin, &next_admin);
    client.accept_admin(&next_admin);

    assert_eq!(client.get_authority_history_count(), 5);

    // Entry 4: second proposal
    let prop2 = client.get_authority_history_at(&4).unwrap();
    assert_eq!(prop2.reference, 4);
    assert_eq!(prop2.transition, TRANSITION_PROPOSED);

    // Entry 5: old admin revoked
    let old_revoked = client.get_authority_history_at(&5).unwrap();
    assert_eq!(old_revoked.reference, 5);
    assert_eq!(old_revoked.approver, admin);
    assert_eq!(old_revoked.role, ROLE_ADMIN);
    assert_eq!(old_revoked.transition, TRANSITION_REVOKED);
    assert_eq!(old_revoked.actor, Some(next_admin.clone()));

    // Entry 6 is actually reference 6 if previous admin revocation was 5, let's verify total
    assert_eq!(client.get_authority_history_count(), 6);
    let new_accepted = client.get_authority_history_at(&6).unwrap();
    assert_eq!(new_accepted.reference, 6);
    assert_eq!(new_accepted.approver, next_admin);
    assert_eq!(new_accepted.role, ROLE_ADMIN);
    assert_eq!(new_accepted.transition, TRANSITION_ACCEPTED);
    assert_eq!(new_accepted.actor, Some(next_admin.clone()));

    // Verify per-approver counts
    assert_eq!(client.get_approver_authority_history_count(&admin), 2); // init (1) + revoked (5)
    assert_eq!(client.get_approver_authority_history_count(&next_admin), 4); // prop (2) + cancel (3) + prop (4) + accept (6)
}

#[test]
fn issuer_lifecycle_records_authority_history_with_metadata_hash() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let issuer1 = Address::generate(&env);
    let issuer2 = Address::generate(&env);
    let meta1 = b32(&env, 0x11);
    let meta2 = b32(&env, 0x22);
    let meta3 = b32(&env, 0x33);

    // Add issuer
    client.add_issuer(&admin, &issuer1, &meta1);
    let add_entry = client.get_authority_history_at(&2).unwrap();
    assert_eq!(add_entry.reference, 2);
    assert_eq!(add_entry.approver, issuer1);
    assert_eq!(add_entry.role, ROLE_ISSUER);
    assert_eq!(add_entry.transition, TRANSITION_ADDED);
    assert_eq!(add_entry.actor, Some(admin.clone()));
    assert_eq!(add_entry.metadata_hash, Some(meta1));

    // Update issuer metadata
    client.update_issuer_metadata(&admin, &issuer1, &meta2);
    let update_entry = client.get_authority_history_at(&3).unwrap();
    assert_eq!(update_entry.reference, 3);
    assert_eq!(update_entry.approver, issuer1);
    assert_eq!(update_entry.role, ROLE_ISSUER);
    assert_eq!(update_entry.transition, TRANSITION_METADATA_UPDATED);
    assert_eq!(update_entry.actor, Some(admin.clone()));
    assert_eq!(update_entry.metadata_hash, Some(meta2));

    // Add replacement issuer and rotate
    client.add_issuer(&admin, &issuer2, &meta3);
    let expires_at = client.rotate_issuer(&admin, &issuer1, &issuer2, &3600);

    let rotate_entry = client.get_authority_history_at(&5).unwrap();
    assert_eq!(rotate_entry.reference, 5);
    assert_eq!(rotate_entry.approver, issuer1);
    assert_eq!(rotate_entry.role, ROLE_ISSUER);
    assert_eq!(rotate_entry.transition, TRANSITION_ROTATED);
    assert_eq!(rotate_entry.actor, Some(admin.clone()));

    // Finalize rotation after grace expires
    env.ledger().set_timestamp(expires_at + 1);
    client.finalize_issuer_rotation(&issuer1);

    let fin_entry = client.get_authority_history_at(&7).unwrap();
    assert_eq!(fin_entry.reference, 7);
    assert_eq!(fin_entry.approver, issuer1);
    assert_eq!(fin_entry.role, ROLE_ISSUER);
    assert_eq!(fin_entry.transition, TRANSITION_FINALIZED);

    // Revoke replacement issuer
    client.revoke_issuer(&admin, &issuer2);
    let revoke_entry = client.get_authority_history_at(&8).unwrap();
    assert_eq!(revoke_entry.reference, 8);
    assert_eq!(revoke_entry.approver, issuer2);
    assert_eq!(revoke_entry.role, ROLE_ISSUER);
    assert_eq!(revoke_entry.transition, TRANSITION_REVOKED);
    assert_eq!(revoke_entry.actor, Some(admin));
}

#[test]
fn guardian_lifecycle_records_authority_history() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let guardian = Address::generate(&env);

    client.set_guardian(&admin, &guardian);
    let set_entry = client.get_authority_history_at(&2).unwrap();
    assert_eq!(set_entry.reference, 2);
    assert_eq!(set_entry.approver, guardian);
    assert_eq!(set_entry.role, ROLE_GUARDIAN);
    assert_eq!(set_entry.transition, TRANSITION_ADDED);
    assert_eq!(set_entry.actor, Some(admin.clone()));

    client.clear_guardian(&admin);
    let clear_entry = client.get_authority_history_at(&3).unwrap();
    assert_eq!(clear_entry.reference, 3);
    assert_eq!(clear_entry.approver, guardian);
    assert_eq!(clear_entry.role, ROLE_GUARDIAN);
    assert_eq!(clear_entry.transition, TRANSITION_REVOKED);
    assert_eq!(clear_entry.actor, Some(admin));
}

#[test]
fn bounded_pagination_and_cursor_navigation() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Init already recorded reference 1
    // Add 4 issuers -> total 5 transitions
    for i in 1..=4 {
        let issuer = Address::generate(&env);
        client.add_issuer(&admin, &issuer, &b32(&env, i));
    }
    assert_eq!(client.get_authority_history_count(), 5);

    // Page 1: offset 0, limit 2 -> entries 1, 2
    let p1 = client.get_institutional_authority_history(&0, &2);
    assert_eq!(p1.entries.len(), 2);
    assert_eq!(p1.entries.get(0).unwrap().reference, 1);
    assert_eq!(p1.entries.get(1).unwrap().reference, 2);
    assert_eq!(p1.next_offset, 2);
    assert_eq!(p1.next_cursor, Some(2));
    assert_eq!(p1.total, 5);

    // Page 2: offset 2, limit 2 -> entries 3, 4
    let p2 = client.get_institutional_authority_history(&p1.next_offset, &2);
    assert_eq!(p2.entries.len(), 2);
    assert_eq!(p2.entries.get(0).unwrap().reference, 3);
    assert_eq!(p2.entries.get(1).unwrap().reference, 4);
    assert_eq!(p2.next_offset, 4);
    assert_eq!(p2.next_cursor, Some(4));

    // Page 3: offset 4, limit 2 -> entry 5 (end reached)
    let p3 = client.get_institutional_authority_history(&p2.next_offset, &2);
    assert_eq!(p3.entries.len(), 1);
    assert_eq!(p3.entries.get(0).unwrap().reference, 5);
    assert_eq!(p3.next_offset, 5);
    assert_eq!(p3.next_cursor, None);

    // Page 4: offset 5, limit 2 -> empty
    let p4 = client.get_institutional_authority_history(&5, &2);
    assert_eq!(p4.entries.len(), 0);
    assert_eq!(p4.next_cursor, None);
    assert_eq!(p4.total, 5);
}

#[test]
fn approver_history_avoids_unbounded_iteration() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let target_issuer = Address::generate(&env);

    // Add noise entries for other issuers
    for i in 1..=3 {
        let other = Address::generate(&env);
        client.add_issuer(&admin, &other, &b32(&env, i));
    }

    // Add target issuer and update metadata
    client.add_issuer(&admin, &target_issuer, &b32(&env, 0xAA));
    client.update_issuer_metadata(&admin, &target_issuer, &b32(&env, 0xBB));

    // Add more noise
    let noise = Address::generate(&env);
    client.add_issuer(&admin, &noise, &b32(&env, 0xCC));

    assert_eq!(client.get_authority_history_count(), 7);
    assert_eq!(client.get_approver_authority_history_count(&target_issuer), 2);

    let page = client.get_approver_authority_history(&target_issuer, &0, &50);
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries.get(0).unwrap().approver, target_issuer);
    assert_eq!(page.entries.get(0).unwrap().transition, TRANSITION_ADDED);
    assert_eq!(page.entries.get(1).unwrap().approver, target_issuer);
    assert_eq!(page.entries.get(1).unwrap().transition, TRANSITION_METADATA_UPDATED);
    assert_eq!(page.total, 2);

    // Unknown approver query does not scan; returns empty page in O(1)
    let unknown = Address::generate(&env);
    let empty_page = client.get_approver_authority_history(&unknown, &0, &50);
    assert_eq!(empty_page.entries.len(), 0);
    assert_eq!(empty_page.total, 0);
    assert_eq!(empty_page.next_cursor, None);

    // Lookup out of bounds returns None
    assert_eq!(client.get_authority_history_at(&0), None);
    assert_eq!(client.get_authority_history_at(&9999), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")] // HistoryLimitExceeded
fn authority_history_rejects_zero_limit() {
    let (env, contract_id, _admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.get_institutional_authority_history(&0, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")] // HistoryLimitExceeded
fn authority_history_rejects_limit_exceeding_cap() {
    let (env, contract_id, _admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.get_institutional_authority_history(&0, &(MAX_AUTHORITY_HISTORY_PAGE + 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")] // HistoryLimitExceeded
fn approver_authority_history_rejects_zero_limit() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.get_approver_authority_history(&admin, &0, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")] // HistoryLimitExceeded
fn approver_authority_history_rejects_limit_exceeding_cap() {
    let (env, contract_id, admin) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.get_approver_authority_history(&admin, &0, &(MAX_AUTHORITY_HISTORY_PAGE + 1));
}
