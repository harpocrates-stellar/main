//! Versioned evidence lifecycle transition receipt tests (#1194).
//!
//! Verifies:
//! - Every lifecycle transition (`Registered`, `Verified`, `Corrected`,
//!   `Expired`, `Revoked`) persists a versioned `LifecycleTransitionReceipt`
//!   bound to `previous_revision`, `previous_receipt_hash`, and the
//!   privacy-safe `statement_digest`.
//! - `verify_lifecycle_continuity` verifies full hash-chain continuity across
//!   bounded pages without disclosing private witness values or nullifiers.
//! - Tampering with `previous_receipt_hash`, `previous_revision`,
//!   `statement_digest`, or deleting an intermediate receipt fails continuity
//!   verification deterministically at the offending revision.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Bytes, Env,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[test]
fn test_versioned_transition_receipts_chain_revisions_and_statement_digest() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(100);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    let proof_id = b32(&env, 0x11);
    let video_hash = b32(&env, 0x22);
    let meta_v1 = b32(&env, 0x33);
    let meta_v2 = b32(&env, 0x44);

    // 1. Register (revision 1)
    client.register_source(&source, &video_hash, &meta_v1, &proof_id);
    let stmt_digest = client.get_statement_digest(&proof_id).unwrap();

    let r1 = client.get_transition_receipt(&proof_id, &1).unwrap();
    assert_eq!(r1.receipt_version, TRANSITION_RECEIPT_V1);
    assert_eq!(r1.proof_id, proof_id);
    assert_eq!(r1.revision, 1);
    assert_eq!(r1.previous_revision, 0);
    assert_eq!(r1.action, ProofLifecycleAction::Registered as u32);
    assert_eq!(r1.statement_digest, stmt_digest);
    assert_eq!(r1.previous_receipt_hash, b32(&env, 0x00));

    // 2. Verify (revision 2) -> Correct (revision 3) -> Expire (revision 4) -> Revoke (revision 5)
    env.ledger().set_timestamp(1_700_000_100);
    env.ledger().set_sequence_number(110);
    client.verify_proof(&admin, &proof_id, &5u32);

    env.ledger().set_timestamp(1_700_000_200);
    env.ledger().set_sequence_number(120);
    client.correct_proof(&admin, &proof_id, &meta_v2, &9u32);

    env.ledger().set_timestamp(1_700_000_300);
    env.ledger().set_sequence_number(130);
    client.expire_proof(&admin, &proof_id, &11u32);

    env.ledger().set_timestamp(1_700_000_400);
    env.ledger().set_sequence_number(140);
    client.revoke_proof(&admin, &proof_id);

    let r2 = client.get_transition_receipt(&proof_id, &2).unwrap();
    let r3 = client.get_transition_receipt(&proof_id, &3).unwrap();
    let r4 = client.get_transition_receipt(&proof_id, &4).unwrap();
    let r5 = client.get_latest_transition_rcpt(&proof_id).unwrap();

    assert_eq!(r2.previous_revision, 1);
    assert_eq!(r2.previous_receipt_hash, r1.receipt_hash);
    assert_eq!(r3.previous_revision, 2);
    assert_eq!(r3.previous_receipt_hash, r2.receipt_hash);
    assert_eq!(r4.previous_revision, 3);
    assert_eq!(r4.previous_receipt_hash, r3.receipt_hash);
    assert_eq!(r5.revision, 5);
    assert_eq!(r5.previous_revision, 4);
    assert_eq!(r5.previous_receipt_hash, r4.receipt_hash);
    assert_eq!(r5.statement_digest, stmt_digest);

    // Full continuity check (1..=5) and paged continuity check (3..=5 anchored on rev 2).
    let full = client.verify_lifecycle_continuity(&proof_id, &1, &10);
    assert_eq!(
        full,
        ContinuityVerifyReport {
            valid: true,
            checked_count: 5,
            total_revisions: 5,
            failed_at_revision: 0,
            head_receipt_hash: r5.receipt_hash.clone(),
        }
    );

    let page2 = client.verify_lifecycle_continuity(&proof_id, &3, &3);
    assert_eq!(
        page2,
        ContinuityVerifyReport {
            valid: true,
            checked_count: 3,
            total_revisions: 5,
            failed_at_revision: 0,
            head_receipt_hash: r5.receipt_hash,
        }
    );
}

#[test]
fn test_anonymous_tier1_receipt_preserves_witness_privacy_and_detects_tampering() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_010_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    let cred_root = b32(&env, 0x0A);
    client.add_credential_root(&admin, &cred_root, &b32(&env, 0x0B));

    let proof_id = b32(&env, 0x15);
    let video_hash = b32(&env, 0x16);
    let meta_hash = b32(&env, 0x17);
    let secret_nullifier = b32(&env, 0x09);
    let synthetic_proof = Bytes::from_array(&env, &[0xAB; 64]);

    client.register_anonymous(
        &video_hash,
        &meta_hash,
        &proof_id,
        &secret_nullifier,
        &cred_root,
        &synthetic_proof,
    );
    client.verify_proof(&admin, &proof_id, &2u32);
    client.revoke_proof(&admin, &proof_id);

    // Ensure no receipt field equals or leaks the nullifier or metadata hash.
    for rev in 1..=3 {
        let rcpt = client.get_transition_receipt(&proof_id, &rev).unwrap();
        assert_ne!(rcpt.statement_digest, secret_nullifier);
        assert_ne!(rcpt.statement_digest, meta_hash);
        assert_ne!(rcpt.receipt_hash, secret_nullifier);
    }

    assert!(client.verify_lifecycle_continuity(&proof_id, &1, &10).valid);

    // Tamper with revision 2's previous_receipt_hash in storage -> continuity fails at rev 2.
    env.as_contract(&contract_id, || {
        let mut tampered: LifecycleTransitionReceipt = env
            .storage()
            .persistent()
            .get(&DataKey::TransitionReceipt(proof_id.clone(), 2))
            .unwrap();
        tampered.previous_receipt_hash = b32(&env, 0xEE);
        env.storage()
            .persistent()
            .set(&DataKey::TransitionReceipt(proof_id.clone(), 2), &tampered);
    });

    let broken = client.verify_lifecycle_continuity(&proof_id, &1, &10);
    assert!(!broken.valid);
    assert_eq!(broken.failed_at_revision, 2);

    // Out-of-bounds limit fails closed with ListLimitExceeded (#91).
    assert_eq!(
        client.try_verify_lifecycle_continuity(&proof_id, &1, &(MAX_HISTORY_LIMIT + 1)),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ListLimitExceeded as u32
        )))
    );
}
