//! Explicit supersession link read method tests (#1197).
//!
//! Verifies:
//! - Explicit supersession links return original and superseding statement
//!   identities alongside live lifecycle status (`Valid`, `Revoked`, `Expired`).
//! - Supersession is NEVER inferred from registration timestamp/event ordering,
//!   revocations, metadata corrections, or non-superseded disputes.
//! - Out-of-order statement registration (`superseding` registered earlier than
//!   `original`) still reports the explicit `original -> superseding` link.
//! - Multi-hop chains (`A -> B -> C`) and pre-#1197 legacy dispute storage
//!   resolve deterministically without mutating contract state.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn setup_registry() -> (
    Env,
    Address,
    HarpocratesRegistryClient<'static>,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xA0));

    (env, contract_id, client, admin, source, issuer)
}

#[test]
fn test_explicit_supersession_link_returns_identities_and_live_lifecycle_status() {
    let (env, _cid, client, admin, source, issuer) = setup_registry();
    let reporter = Address::generate(&env);

    let orig_id = b32(&env, 0x11);
    let new_id = b32(&env, 0x22);
    let dispute_id = b32(&env, 0xD1);

    client.register_source(&source, &b32(&env, 0x12), &b32(&env, 0x13), &orig_id);
    env.ledger().set_timestamp(1_700_000_100);
    client.register_seal(&issuer, &b32(&env, 0x23), &b32(&env, 0x24), &new_id);

    // Before explicit supersession, neither statement has a supersession link.
    assert_eq!(client.get_supersession_link(&orig_id), None);
    assert_eq!(client.get_supersession_link(&new_id), None);

    client.open_dispute(
        &reporter,
        &b32(&env, 0x81),
        &dispute_id,
        &orig_id,
        &DisputeReason::MetadataError,
        &b32(&env, 0x91),
    );
    env.ledger().set_timestamp(1_700_000_500);
    client.supersede_dispute(&admin, &dispute_id, &new_id);

    let expected = SupersessionLink {
        original_proof_id: orig_id.clone(),
        original_status: ProofVerificationStatus::Valid,
        original_tier: TIER_CONSISTENT_SOURCE,
        superseding_proof_id: new_id.clone(),
        superseding_status: ProofVerificationStatus::Valid,
        superseding_tier: TIER_PUBLIC_SEAL,
        dispute_id: dispute_id.clone(),
        linked_at: 1_700_000_500,
    };

    assert_eq!(
        client.get_supersession_link(&orig_id),
        Some(expected.clone())
    );
    assert_eq!(
        client.get_supersession_link(&new_id),
        Some(expected.clone())
    );
    assert_eq!(
        client.get_supersession_by_orig(&orig_id),
        Some(expected.clone())
    );
    assert_eq!(client.get_supersession_by_orig(&new_id), None);
    assert_eq!(
        client.get_supersession_by_new(&new_id),
        Some(expected.clone())
    );
    assert_eq!(client.get_supersession_by_new(&orig_id), None);
    assert_eq!(client.get_dispute_supersession(&dispute_id), Some(expected));

    // Lifecycle transitions on the original and superseding statements reflect live status.
    client.revoke_proof(&admin, &orig_id);
    let after_revoke = client.get_supersession_link(&orig_id).unwrap();
    assert_eq!(
        after_revoke.original_status,
        ProofVerificationStatus::Revoked
    );
    assert_eq!(
        after_revoke.superseding_status,
        ProofVerificationStatus::Valid
    );

    client.expire_proof(&admin, &new_id, &7u32);
    let after_expire = client.get_supersession_link(&new_id).unwrap();
    assert_eq!(
        after_expire.original_status,
        ProofVerificationStatus::Revoked
    );
    assert_eq!(
        after_expire.superseding_status,
        ProofVerificationStatus::Expired
    );
}

#[test]
fn test_supersession_never_inferred_from_event_ordering_alone() {
    let (env, _cid, client, admin, _source, issuer) = setup_registry();
    let reporter = Address::generate(&env);

    let first_id = b32(&env, 0x31);
    let second_id = b32(&env, 0x32);
    let third_id = b32(&env, 0x33);

    // Register sequential statements by the same issuer across advancing timestamps.
    client.register_seal(&issuer, &b32(&env, 0x41), &b32(&env, 0x51), &first_id);
    env.ledger().set_timestamp(1_700_001_000);
    client.register_seal(&issuer, &b32(&env, 0x42), &b32(&env, 0x52), &second_id);
    env.ledger().set_timestamp(1_700_002_000);
    client.register_seal(&issuer, &b32(&env, 0x43), &b32(&env, 0x53), &third_id);

    // Revoke first, correct second, and open/respond/resolve/dismiss disputes without superseding.
    client.revoke_proof(&admin, &first_id);
    client.correct_proof(&admin, &second_id, &b32(&env, 0x59), &2u32);

    let open_dispute_id = b32(&env, 0xE1);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x71),
        &open_dispute_id,
        &first_id,
        &DisputeReason::ContentError,
        &b32(&env, 0x61),
    );

    let resolved_dispute_id = b32(&env, 0xE2);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x72),
        &resolved_dispute_id,
        &second_id,
        &DisputeReason::MetadataError,
        &b32(&env, 0x62),
    );
    client.respond_dispute(&issuer, &resolved_dispute_id, &b32(&env, 0x63));
    client.resolve_dispute(&admin, &resolved_dispute_id);

    let dismissed_dispute_id = b32(&env, 0xE3);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x73),
        &dismissed_dispute_id,
        &third_id,
        &DisputeReason::Other,
        &b32(&env, 0x64),
    );
    client.dismiss_dispute(&admin, &dismissed_dispute_id);

    // None of these chronological lifecycle events may imply supersession.
    for id in [&first_id, &second_id, &third_id] {
        assert_eq!(client.get_supersession_link(id), None);
        assert_eq!(client.get_supersession_by_orig(id), None);
        assert_eq!(client.get_supersession_by_new(id), None);
    }
    for d_id in [
        &open_dispute_id,
        &resolved_dispute_id,
        &dismissed_dispute_id,
    ] {
        assert_eq!(client.get_dispute_supersession(d_id), None);
    }
    assert_eq!(client.get_supersession_link(&b32(&env, 0xFF)), None);
    assert_eq!(client.get_dispute_supersession(&b32(&env, 0xFE)), None);
}

#[test]
fn test_out_of_order_registration_preserves_explicit_direction_and_chain() {
    let (env, contract_id, client, admin, source, _issuer) = setup_registry();
    let reporter = Address::generate(&env);

    // Register `replacement_early` BEFORE `original_late` in ledger time.
    let replacement_early = b32(&env, 0xA1);
    let original_late = b32(&env, 0xA2);
    let final_replacement = b32(&env, 0xA3);

    client.register_source(
        &source,
        &b32(&env, 0xB1),
        &b32(&env, 0xC1),
        &replacement_early,
    );
    env.ledger().set_timestamp(1_700_010_000);
    client.register_source(&source, &b32(&env, 0xB2), &b32(&env, 0xC2), &original_late);
    env.ledger().set_timestamp(1_700_020_000);
    client.register_source(
        &source,
        &b32(&env, 0xB3),
        &b32(&env, 0xC3),
        &final_replacement,
    );

    let d1 = b32(&env, 0xD4);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x94),
        &d1,
        &original_late,
        &DisputeReason::ContentError,
        &b32(&env, 0x84),
    );
    client.supersede_dispute(&admin, &d1, &replacement_early);

    let link_1 = client.get_supersession_link(&original_late).unwrap();
    assert_eq!(link_1.original_proof_id, original_late);
    assert_eq!(link_1.superseding_proof_id, replacement_early);

    // Chain: replacement_early is later superseded by final_replacement.
    let d2 = b32(&env, 0xD5);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x95),
        &d2,
        &replacement_early,
        &DisputeReason::MetadataError,
        &b32(&env, 0x85),
    );
    client.supersede_dispute(&admin, &d2, &final_replacement);

    // `replacement_early` has both an outgoing link (to `final_replacement`) and an incoming link (from `original_late`).
    assert_eq!(
        client
            .get_supersession_by_orig(&replacement_early)
            .unwrap()
            .superseding_proof_id,
        final_replacement
    );
    assert_eq!(
        client
            .get_supersession_by_new(&replacement_early)
            .unwrap()
            .original_proof_id,
        original_late
    );
    assert_eq!(
        client
            .get_supersession_link(&replacement_early)
            .unwrap()
            .superseding_proof_id,
        final_replacement
    );

    // Simulate pre-#1197 storage by removing `SupersessionOut` / `SupersessionIn` keys and verifying bounded fallback.
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .remove(&DataKey::SupersessionOut(original_late.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::SupersessionIn(replacement_early.clone()));
    });
    let legacy_out = client.get_supersession_by_orig(&original_late).unwrap();
    assert_eq!(legacy_out.original_proof_id, original_late);
    assert_eq!(legacy_out.superseding_proof_id, replacement_early);
    let legacy_in = client.get_supersession_by_new(&replacement_early).unwrap();
    assert_eq!(legacy_in.original_proof_id, original_late);
    assert_eq!(legacy_in.superseding_proof_id, replacement_early);
}
