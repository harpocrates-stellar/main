//! Tests for revoked proof status with recorded effective ledger (#1200).

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn b32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

#[test]
fn revoked_proof_status_keeps_effective_ledger_distinct_from_query_ledger_and_preserves_identity() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    env.ledger().set_sequence_number(100);
    env.ledger().set_timestamp(1_700_000_000);

    let proof_id = b32(&env, 0x11);
    let video_hash = b32(&env, 0x22);
    let metadata_hash = b32(&env, 0x33);

    let registered = client.register_source(&source, &video_hash, &metadata_hash, &proof_id);
    assert_eq!(registered.created_at, 1_700_000_000);

    // Before revocation: status is Valid, effective_ledger is None.
    env.ledger().set_sequence_number(150);
    let active_view = client.get_revoked_proof_status(&proof_id);
    assert_eq!(active_view.proof_id, proof_id);
    assert_eq!(active_view.status, ProofVerificationStatus::Valid);
    assert!(!active_view.is_revoked);
    assert_eq!(active_view.effective_ledger, None);
    assert_eq!(active_view.revoked_at, None);
    assert_eq!(active_view.query_ledger, 150);
    assert_eq!(active_view.video_hash, Some(video_hash.clone()));
    assert_eq!(active_view.metadata_hash, Some(metadata_hash.clone()));
    assert_eq!(active_view.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(client.get_proof_revocation(&proof_id), None);

    // Revoke at ledger 250, timestamp 1_700_000_750.
    env.ledger().set_sequence_number(250);
    env.ledger().set_timestamp(1_700_000_750);
    client.revoke_proof(&admin, &proof_id);

    // Query much later at ledger 900: effective_ledger stays 250 while query_ledger is 900.
    env.ledger().set_sequence_number(900);
    env.ledger().set_timestamp(1_700_050_000);
    let revoked_view = client.get_revoked_proof_status(&proof_id);
    assert_eq!(revoked_view.status, ProofVerificationStatus::Revoked);
    assert!(revoked_view.is_revoked);
    assert_eq!(revoked_view.effective_ledger, Some(250));
    assert_eq!(revoked_view.revoked_at, Some(1_700_000_750));
    assert_eq!(revoked_view.query_ledger, 900);
    assert_ne!(
        revoked_view.effective_ledger,
        Some(revoked_view.query_ledger)
    );

    // Statement identity fields are completely preserved across revocation.
    assert_eq!(revoked_view.video_hash, Some(video_hash.clone()));
    assert_eq!(revoked_view.metadata_hash, Some(metadata_hash.clone()));
    assert_eq!(revoked_view.tier, TIER_CONSISTENT_SOURCE);

    let stored = client.get_proof(&proof_id).unwrap();
    assert_eq!(stored.video_hash, video_hash);
    assert_eq!(stored.metadata_hash, metadata_hash);
    assert_eq!(stored.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(stored.created_at, 1_700_000_000);
    assert_eq!(stored.source, Some(source));
}

#[test]
fn repeat_revoke_and_batch_revoke_preserve_first_effective_ledger() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xA0));

    env.ledger().set_sequence_number(40);
    env.ledger().set_timestamp(1_700_100_000);
    let proof_a = b32(&env, 0x41);
    let proof_b = b32(&env, 0x42);
    client.register_seal(&issuer, &b32(&env, 0x51), &b32(&env, 0x61), &proof_a);
    client.register_seal(&issuer, &b32(&env, 0x52), &b32(&env, 0x62), &proof_b);

    // Batch revoke at ledger 310.
    env.ledger().set_sequence_number(310);
    env.ledger().set_timestamp(1_700_101_000);
    let mut batch = Vec::new(&env);
    batch.push_back(proof_a.clone());
    batch.push_back(proof_b.clone());
    client.revoke_proofs(&admin, &batch, &7);

    // Re-revoking proof_a at ledger 777 must NOT overwrite the original effective_ledger (310).
    env.ledger().set_sequence_number(777);
    env.ledger().set_timestamp(1_700_200_000);
    client.revoke_proof(&admin, &proof_a);

    env.ledger().set_sequence_number(1200);
    let view_a = client.get_revoked_proof_status(&proof_a);
    let view_b = client.get_revoked_proof_status(&proof_b);
    assert_eq!(view_a.effective_ledger, Some(310));
    assert_eq!(view_a.revoked_at, Some(1_700_101_000));
    assert_eq!(view_a.query_ledger, 1200);
    assert_eq!(view_b.effective_ledger, Some(310));
    assert_eq!(view_b.query_ledger, 1200);
}

#[test]
fn unknown_expired_and_legacy_revoked_boundary_cases_never_fabricate_effective_ledger() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    env.ledger().set_sequence_number(500);
    env.ledger().set_timestamp(1_700_300_000);

    // 1. Unknown proof boundary: NotFound, is_revoked = false, no fabricated ledger.
    let missing_id = b32(&env, 0xFE);
    let missing = client.get_revoked_proof_status(&missing_id);
    assert_eq!(missing.status, ProofVerificationStatus::NotFound);
    assert!(!missing.is_revoked);
    assert_eq!(missing.effective_ledger, None);
    assert_eq!(missing.revoked_at, None);
    assert_eq!(missing.query_ledger, 500);
    assert_eq!(missing.video_hash, None);
    assert_eq!(missing.metadata_hash, None);
    assert_eq!(missing.tier, 0);

    // 2. Expired proof boundary: Expired is distinct from Revoked (`is_revoked = false`).
    let expired_id = b32(&env, 0xFD);
    client.register_source(&source, &b32(&env, 0xED), &b32(&env, 0xEC), &expired_id);
    client.expire_proof(&admin, &expired_id, &2);
    env.ledger().set_sequence_number(520);
    let expired_view = client.get_revoked_proof_status(&expired_id);
    assert_eq!(expired_view.status, ProofVerificationStatus::Expired);
    assert!(!expired_view.is_revoked);
    assert_eq!(expired_view.effective_ledger, None);
    assert_eq!(expired_view.revoked_at, None);
    assert_eq!(expired_view.query_ledger, 520);

    // 3. Pre-#1200 legacy revoked record without `DataKey::ProofRevocation`:
    // reports `is_revoked = true` with `effective_ledger = None` (never fabricates `query_ledger`).
    let legacy_id = b32(&env, 0xFC);
    let legacy_video = b32(&env, 0xEB);
    let legacy_meta = b32(&env, 0xEA);
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(
            &DataKey::Proof(legacy_id.clone()),
            &ProofRecord {
                video_hash: legacy_video.clone(),
                metadata_hash: legacy_meta.clone(),
                tier: TIER_SILENT_WITNESS,
                status: STATUS_REVOKED,
                created_at: 1_700_000_000,
                expires_at: 0,
                source: None,
                issuer: None,
                nullifier: Some(b32(&env, 0xE9)),
                batch_size: 0,
            },
        );
    });
    env.ledger().set_sequence_number(888);
    let legacy_view = client.get_revoked_proof_status(&legacy_id);
    assert_eq!(legacy_view.status, ProofVerificationStatus::Revoked);
    assert!(legacy_view.is_revoked);
    assert_eq!(legacy_view.effective_ledger, None);
    assert_eq!(legacy_view.revoked_at, None);
    assert_eq!(legacy_view.query_ledger, 888);
    assert_eq!(legacy_view.video_hash, Some(legacy_video));
    assert_eq!(legacy_view.metadata_hash, Some(legacy_meta));
    assert_eq!(legacy_view.tier, TIER_SILENT_WITNESS);
}
