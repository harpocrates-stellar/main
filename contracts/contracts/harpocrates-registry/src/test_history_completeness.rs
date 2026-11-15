//! Proof-history completeness, truncation, and predecessor metadata tests (#1203).

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    Address, Bytes, BytesN, Env,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn assert_registry_error<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
    expected: RegistryError,
) {
    assert_eq!(
        res.err(),
        Some(Ok(soroban_sdk::Error::from_contract_error(expected as u32)))
    );
}

fn setup_registry() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, contract_id, admin)
}

#[test]
fn complete_single_page_reports_untruncated_without_predecessor() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x11);

    env.ledger().set_timestamp(1_000);
    client.register_source(&source, &b32(&env, 0x21), &b32(&env, 0x31), &proof_id);
    env.ledger().set_timestamp(1_050);
    client.verify_proof(&admin, &proof_id, &7);
    env.ledger().set_timestamp(1_100);
    client.correct_proof(&admin, &proof_id, &b32(&env, 0x32), &12);

    let page = client.get_proof_history(&proof_id, &0, &10);
    let alias_page = client.get_proof_history_page(&proof_id, &0, &10);
    assert_eq!(page, alias_page);

    assert_eq!(page.total_entries, 3);
    assert_eq!(page.offset, 0);
    assert_eq!(page.limit, 10);
    assert_eq!(page.entries.len(), 3);
    assert!(page.is_complete);
    assert!(!page.truncated);
    assert!(!page.has_older_entries);
    assert!(!page.has_newer_entries);
    assert_eq!(page.predecessor_seq, None);
    assert_eq!(page.predecessor_action, None);
    assert_eq!(page.predecessor_timestamp, None);
    assert_eq!(page.predecessor_actor, None);
    assert_eq!(page.predecessor_reason_code, None);
    assert_eq!(page.next_offset, None);

    // Existing random-access and count queries remain intact.
    assert_eq!(client.get_proof_history_count(&proof_id), 3);
    for seq in 1..=3u32 {
        assert_eq!(
            page.entries.get(seq - 1).unwrap(),
            client.get_proof_history_at(&proof_id, &seq).unwrap()
        );
    }
}

#[test]
fn partial_pages_report_truncation_and_chain_predecessors_explicitly() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x44);

    env.ledger().set_timestamp(2_000);
    client.register_source(&source, &b32(&env, 0x45), &b32(&env, 0x46), &proof_id);
    env.ledger().set_timestamp(2_010);
    client.verify_proof(&admin, &proof_id, &1);
    env.ledger().set_timestamp(2_020);
    client.correct_proof(&admin, &proof_id, &b32(&env, 0x47), &2);
    env.ledger().set_timestamp(2_030);
    client.expire_proof(&admin, &proof_id, &3);
    env.ledger().set_timestamp(2_040);
    client.revoke_proof(&admin, &proof_id);

    assert_eq!(client.get_proof_history_count(&proof_id), 5);

    // Page 1 (head slice [1, 2]): incomplete, newer entries follow, no predecessor.
    let p1 = client.get_proof_history_page(&proof_id, &0, &2);
    assert_eq!(p1.entries.len(), 2);
    assert_eq!(p1.total_entries, 5);
    assert!(!p1.is_complete);
    assert!(p1.truncated);
    assert!(!p1.has_older_entries);
    assert!(p1.has_newer_entries);
    assert_eq!(p1.predecessor_seq, None);
    assert_eq!(p1.next_offset, Some(2));
    assert_eq!(
        p1.entries.get(0).unwrap().action,
        ProofLifecycleAction::Registered as u32
    );
    assert_eq!(
        p1.entries.get(1).unwrap().action,
        ProofLifecycleAction::Verified as u32
    );

    // Page 2 (middle slice [3, 4]): incomplete, both older & newer exist, predecessor is seq 2.
    let p2 = client.get_proof_history_page(&proof_id, &p1.next_offset.unwrap(), &2);
    let expected_pred_p2 = client.get_proof_history_at(&proof_id, &2).unwrap();
    assert_eq!(p2.entries.len(), 2);
    assert!(!p2.is_complete);
    assert!(p2.truncated);
    assert!(p2.has_older_entries);
    assert!(p2.has_newer_entries);
    assert_eq!(p2.predecessor_seq, Some(2));
    assert_eq!(p2.predecessor_action, Some(expected_pred_p2.action));
    assert_eq!(p2.predecessor_timestamp, Some(expected_pred_p2.timestamp));
    assert_eq!(p2.predecessor_actor, expected_pred_p2.actor);
    assert_eq!(
        p2.predecessor_reason_code,
        Some(expected_pred_p2.reason_code)
    );
    assert_eq!(p2.next_offset, Some(4));
    assert_eq!(
        p2.entries.get(0).unwrap().action,
        ProofLifecycleAction::Corrected as u32
    );
    assert_eq!(
        p2.entries.get(1).unwrap().action,
        ProofLifecycleAction::Expired as u32
    );

    // Page 3 (tail slice [5]): STILL incomplete because older entries [1..=4] were omitted!
    let p3 = client.get_proof_history_page(&proof_id, &p2.next_offset.unwrap(), &2);
    let expected_pred_p3 = client.get_proof_history_at(&proof_id, &4).unwrap();
    assert_eq!(p3.entries.len(), 1);
    assert!(!p3.is_complete);
    assert!(p3.truncated);
    assert!(p3.has_older_entries);
    assert!(!p3.has_newer_entries);
    assert_eq!(p3.predecessor_seq, Some(4));
    assert_eq!(p3.predecessor_action, Some(expected_pred_p3.action));
    assert_eq!(p3.predecessor_timestamp, Some(expected_pred_p3.timestamp));
    assert_eq!(p3.predecessor_actor, expected_pred_p3.actor);
    assert_eq!(
        p3.predecessor_reason_code,
        Some(expected_pred_p3.reason_code)
    );
    assert_eq!(p3.next_offset, None);
    assert_eq!(
        p3.entries.get(0).unwrap().action,
        ProofLifecycleAction::Revoked as u32
    );
}

#[test]
fn partial_window_is_never_marked_complete_across_all_offsets_and_limits() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x55);

    client.register_source(&source, &b32(&env, 0x56), &b32(&env, 0x57), &proof_id);
    for reason in 1..=4u32 {
        client.verify_proof(&admin, &proof_id, &reason);
    }
    assert_eq!(client.get_proof_history_count(&proof_id), 5);

    for offset in 0..=7u32 {
        for limit in 0..=7u32 {
            let page = client.get_proof_history(&proof_id, &offset, &limit);
            let expected_complete = offset == 0 && limit >= 5;
            assert_eq!(
                page.is_complete, expected_complete,
                "offset={offset} limit={limit} misreported completeness"
            );
            assert_eq!(
                page.truncated, !expected_complete,
                "offset={offset} limit={limit} misreported truncation"
            );
            if offset > 0 {
                assert_eq!(page.predecessor_seq, Some(offset.min(5)));
            } else {
                assert_eq!(page.predecessor_seq, None);
            }
        }
    }
}

#[test]
fn anonymous_predecessor_preserves_privacy_safe_none_actor() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let cred_root = b32(&env, 0x61);
    client.add_credential_root(&admin, &cred_root, &b32(&env, 0x62));

    let proof_id = b32(&env, 0x63);
    env.ledger().set_timestamp(3_000);
    client.register_anonymous(
        &b32(&env, 0x64),
        &b32(&env, 0x65),
        &proof_id,
        &b32(&env, 0x66),
        &cred_root,
        &Bytes::from_array(&env, &[0xAA, 0xBB, 0xCC, 0xDD]),
    );
    env.ledger().set_timestamp(3_050);
    client.verify_proof(&admin, &proof_id, &9);

    let tail = client.get_proof_history_page(&proof_id, &1, &5);
    assert_eq!(tail.entries.len(), 1);
    assert!(!tail.is_complete);
    assert!(tail.truncated);
    assert_eq!(tail.predecessor_seq, Some(1));
    assert_eq!(
        tail.predecessor_action,
        Some(ProofLifecycleAction::Registered as u32)
    );
    assert_eq!(tail.predecessor_timestamp, Some(3_000));
    assert_eq!(tail.predecessor_actor, None);
    assert_eq!(tail.predecessor_reason_code, Some(1));
}

#[test]
fn multi_page_walk_above_max_history_limit_reconstructs_full_sequence() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x71);

    client.register_source(&source, &b32(&env, 0x72), &b32(&env, 0x73), &proof_id);
    for step in 1..55u32 {
        client.verify_proof(&admin, &proof_id, &(step % 200));
    }
    assert_eq!(client.get_proof_history_count(&proof_id), 55);

    let first = client.get_proof_history_page(&proof_id, &0, &MAX_HISTORY_LIMIT);
    assert_eq!(first.entries.len(), MAX_HISTORY_LIMIT);
    assert!(!first.is_complete);
    assert!(first.truncated);
    assert!(!first.has_older_entries);
    assert!(first.has_newer_entries);
    assert_eq!(first.predecessor_seq, None);
    assert_eq!(first.next_offset, Some(50));

    let second = client.get_proof_history_page(&proof_id, &50, &MAX_HISTORY_LIMIT);
    assert_eq!(second.entries.len(), 5);
    assert!(!second.is_complete);
    assert!(second.truncated);
    assert!(second.has_older_entries);
    assert!(!second.has_newer_entries);
    assert_eq!(second.predecessor_seq, Some(50));
    assert_eq!(second.next_offset, None);
}

#[test]
fn unknown_or_legacy_zero_history_proof_handles_zero_and_nonzero_offsets() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let unknown = b32(&env, 0x81);

    // Pause all domains to prove bounded history reads remain pause-independent and event-free.
    client.pause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &600);

    let at_zero = client.get_proof_history_page(&unknown, &0, &10);
    assert!(env.events().all().events().is_empty());
    assert_eq!(at_zero.entries.len(), 0);
    assert_eq!(at_zero.total_entries, 0);
    assert!(at_zero.is_complete);
    assert!(!at_zero.truncated);
    assert!(!at_zero.has_older_entries);
    assert!(!at_zero.has_newer_entries);
    assert_eq!(at_zero.predecessor_seq, None);
    assert_eq!(at_zero.next_offset, None);

    let nonzero_offset = client.get_proof_history_page(&unknown, &4, &10);
    assert_eq!(nonzero_offset.entries.len(), 0);
    assert_eq!(nonzero_offset.total_entries, 0);
    assert!(!nonzero_offset.is_complete);
    assert!(!nonzero_offset.truncated);
    assert_eq!(nonzero_offset.predecessor_seq, None);
    assert_eq!(nonzero_offset.next_offset, None);
}

#[test]
fn rejects_oversized_limit_and_detects_missing_entry_or_predecessor_corruption() {
    let (env, contract_id, admin) = setup_registry();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x91);

    client.register_source(&source, &b32(&env, 0x92), &b32(&env, 0x93), &proof_id);
    client.verify_proof(&admin, &proof_id, &5);
    client.verify_proof(&admin, &proof_id, &6);

    assert_registry_error(
        client.try_get_proof_history(&proof_id, &0, &(MAX_HISTORY_LIMIT + 1)),
        RegistryError::HistoryLimitExceeded,
    );
    assert_registry_error(
        client.try_get_proof_history_page(&proof_id, &0, &u32::MAX),
        RegistryError::HistoryLimitExceeded,
    );

    // Corrupt slot 2: both a page covering slot 2 AND a tail page starting at offset 2
    // (whose predecessor is slot 2) must fail closed with HistoryCorruption.
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .remove(&DataKey::ProofHistoryEntry(proof_id.clone(), 2));
    });

    assert_registry_error(
        client.try_get_proof_history_page(&proof_id, &0, &3),
        RegistryError::HistoryCorruption,
    );
    assert_registry_error(
        client.try_get_proof_history_page(&proof_id, &2, &1),
        RegistryError::HistoryCorruption,
    );
}
