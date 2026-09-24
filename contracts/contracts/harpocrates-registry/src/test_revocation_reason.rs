//! Revocation reason-code tests (#327)
//!
//! `revoke_proof_with_reason` records a bounded `0..=MAX_REASON_CODE` reason
//! that `get_revocation_reason` returns verbatim. Coverage:
//!
//!   - Positive: explicit reason round-trips through storage, the
//!     `ProofRevoked` event, and lifecycle history.
//!   - Regression: `revoke_proof` keeps its signature and records
//!     `REVOCATION_REASON_DEFAULT`, matching the history reason it always
//!     wrote.
//!   - Negative: non-admin callers, out-of-range codes, and unknown proofs
//!     fail deterministically with typed errors and leave storage untouched.
//!   - Boundary: 0 and 255 are accepted, 256 is rejected.
//!   - Migration: pre-#327 revocations (no `RevocationReason` key) read as
//!     `REVOCATION_REASON_UNSPECIFIED` without rewriting stored evidence.
//!
//! Responses carry only the bounded code — never media, secrets, witness
//! values, or private keys — and reads emit no events.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, testutils::Events as _};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Fresh registry with an admin and one Tier-2 proof ready for revocation.
#[cfg(test)]
fn setup_with_proof(seed: u8) -> (Env, HarpocratesRegistryClient<'static>, Address, BytesN<32>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, seed);

    client.init(&admin);
    client.register_source(
        &source,
        &b32(&env, seed ^ 0x5A),
        &b32(&env, seed ^ 0xA5),
        &proof_id,
    );
    (env, client, admin, proof_id)
}

// ---------------------------------------------------------------------------
// Positive: explicit reason round-trip
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_round_trip() {
    let (env, client, admin, proof_id) = setup_with_proof(0xA1);

    // Not revoked yet: no reason recorded.
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );

    // Revoke emits ProofRevoked + ProofHistoryEvent.
    client.revoke_proof_with_reason(&admin, &proof_id, &42);
    assert_eq!(env.events().all().events().len(), 2);

    assert_eq!(client.get_revocation_reason(&proof_id), 42);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Revoked
    );

    // Lifecycle history records the same bounded code and the authorizing
    // admin.
    let count = client.get_proof_history_count(&proof_id);
    let last = client.get_proof_history_at(&proof_id, &count).unwrap();
    assert_eq!(last.action, ProofLifecycleAction::Revoked as u32);
    assert_eq!(last.reason_code, 42);
    assert_eq!(last.actor, Some(admin));
}

// ---------------------------------------------------------------------------
// Regression: compatibility entry point unchanged
// ---------------------------------------------------------------------------

#[test]
fn revoke_proof_default_records_default_reason() {
    let (env, client, admin, proof_id) = setup_with_proof(0xB1);

    // Signature and event count of the existing path are unchanged.
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(env.events().all().events().len(), 2);

    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_DEFAULT
    );
    let count = client.get_proof_history_count(&proof_id);
    let last = client.get_proof_history_at(&proof_id, &count).unwrap();
    // The compatibility path keeps writing the same history reason it always
    // wrote (1), now mirrored by the stored revocation reason.
    assert_eq!(last.reason_code, REVOCATION_REASON_DEFAULT);
}

// ---------------------------------------------------------------------------
// Reads: unspecified for unknown, non-revoked, and expired proofs
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_unknown_proof_is_unspecified() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    // A read must never panic for malformed/unknown identifiers.
    assert_eq!(
        client.get_revocation_reason(&b32(&env, 0xEE)),
        REVOCATION_REASON_UNSPECIFIED
    );
}

#[test]
fn revocation_reason_active_proof_is_unspecified() {
    let (_env, client, _admin, proof_id) = setup_with_proof(0xC1);
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
}

#[test]
fn revocation_reason_expired_proof_is_unspecified() {
    let (_env, client, admin, proof_id) = setup_with_proof(0xD1);

    // Expiry is not revocation: an expired proof carries no revocation
    // reason, and the two states stay independently observable.
    client.expire_proof(&admin, &proof_id, &2);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Expired
    );
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
}

// ---------------------------------------------------------------------------
// Negative: authorization, bounds, unknown proofs — no side effects
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_non_admin_rejected_without_side_effects() {
    let (_env, client, _admin, proof_id) = setup_with_proof(0xE1);
    let stranger = Address::generate(&_env);

    let result = client.try_revoke_proof_with_reason(&stranger, &proof_id, &7);
    assert!(result.is_err());

    // Storage unchanged; no reason recorded; proof still valid.
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
}

#[test]
fn revocation_reason_out_of_range_rejected_without_side_effects() {
    let (env, client, admin, proof_id) = setup_with_proof(0xE2);

    let result = client.try_revoke_proof_with_reason(&admin, &proof_id, &(MAX_REASON_CODE + 1));
    assert!(result.is_err());

    // Failed calls emit no events and leave storage unchanged.
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
    assert_eq!(client.get_proof_history_count(&proof_id), 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn revocation_reason_unknown_proof_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    client.revoke_proof_with_reason(&admin, &b32(&env, 0xEE), &7);
}

// ---------------------------------------------------------------------------
// Boundary: 0 and 255 accepted, 256 rejected
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_accepts_upper_bound() {
    let (_env, client, admin, proof_id) = setup_with_proof(0xF1);
    client.revoke_proof_with_reason(&admin, &proof_id, &MAX_REASON_CODE);
    assert_eq!(client.get_revocation_reason(&proof_id), MAX_REASON_CODE);
}

#[test]
fn revocation_reason_accepts_zero() {
    let (_env, client, admin, proof_id) = setup_with_proof(0xF2);
    // 0 is the explicit form of "no specific reason" and stays in range.
    client.revoke_proof_with_reason(&admin, &proof_id, &0);
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
}

// ---------------------------------------------------------------------------
// Re-revocation: last reason wins, history stays append-only
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_rerevocation_updates_and_appends() {
    let (_env, client, admin, proof_id) = setup_with_proof(0x1A);

    client.revoke_proof_with_reason(&admin, &proof_id, &5);
    client.revoke_proof_with_reason(&admin, &proof_id, &9);

    // Stored reason reflects the latest revocation...
    assert_eq!(client.get_revocation_reason(&proof_id), 9);
    // ...while history keeps the full, append-only audit trail.
    assert_eq!(client.get_proof_history_count(&proof_id), 3);
    let last = client
        .get_proof_history_at(&proof_id, &client.get_proof_history_count(&proof_id))
        .unwrap();
    assert_eq!(last.action, ProofLifecycleAction::Revoked as u32);
    assert_eq!(last.reason_code, 9);
}

// ---------------------------------------------------------------------------
// Migration: pre-#327 storage reads as unspecified
// ---------------------------------------------------------------------------

#[test]
fn legacy_revocation_without_reason_key_reads_unspecified() {
    let (env, client, admin, proof_id) = setup_with_proof(0x2A);
    let contract_id = client.address.clone();

    client.revoke_proof(&admin, &proof_id);

    // Simulate a pre-#327 deployment: the proof is revoked but the additive
    // `RevocationReason` key was never written.
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .remove(&DataKey::RevocationReason(proof_id.clone()));
    });

    // The read degrades to UNSPECIFIED without rewriting stored evidence.
    assert_eq!(
        client.get_revocation_reason(&proof_id),
        REVOCATION_REASON_UNSPECIFIED
    );
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Revoked
    );
}

// ---------------------------------------------------------------------------
// Privacy: reads emit no events
// ---------------------------------------------------------------------------

#[test]
fn revocation_reason_read_emits_no_events() {
    let (env, client, admin, proof_id) = setup_with_proof(0x3A);
    client.revoke_proof_with_reason(&admin, &proof_id, &3);

    // Most recent invocation is the read; it must not emit.
    let _ = client.get_revocation_reason(&proof_id);
    assert_eq!(env.events().all().events().len(), 0);
}
