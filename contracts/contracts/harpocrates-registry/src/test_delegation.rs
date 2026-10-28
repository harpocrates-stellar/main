//! Constrained issuer and source delegation (#192)
//!
//! Rules under test:
//!
//! 1. A delegation grants exactly the scopes named, for exactly the window
//!    granted, and nothing else.
//! 2. Delegation is not authority: a delegate cannot reach admin, issuer, or
//!    credential-root entry points, and cannot register outside its scope.
//! 3. Delegation is not transitive: a delegate cannot create, extend, or pass
//!    on the authority it received.
//! 4. Delegations expire on their own; a forgotten grant cannot become
//!    permanent authority.
//! 5. Revocation is immediate and available to both the grantor and the admin;
//!    revoking something absent is a no-op, not an error.
//! 6. Storage is bounded: a grantor holds at most
//!    `MAX_DELEGATIONS_PER_GRANTOR` distinct delegates, and re-granting to an
//!    existing delegate is idempotent in storage.
//! 7. Attribution survives: the proof names the grantor, the history names the
//!    delegate.
//! 8. Delegated registration obeys every rule direct registration obeys —
//!    pause domains, uniqueness, and issuer standing.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Env};

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Returns (env, contract_id, admin, grantor, delegate) at `start_ts`.
#[cfg(test)]
fn setup(start_ts: u64) -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let grantor = Address::generate(&env);
    let delegate = Address::generate(&env);

    client.init(&admin);

    (env, contract_id, admin, grantor, delegate)
}

#[cfg(test)]
const ONE_DAY: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Granting
// ---------------------------------------------------------------------------

#[test]
fn grant_stores_a_scoped_expiring_record() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let expires_at = client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert_eq!(expires_at, 1_000 + ONE_DAY);

    let record = client.get_delegation(&grantor, &delegate).unwrap();
    assert_eq!(record.grantor, grantor);
    assert_eq!(record.delegate, delegate);
    assert_eq!(record.scope, DELEGATION_SCOPE_REGISTER_SOURCE);
    assert_eq!(record.granted_at, 1_000);
    assert_eq!(record.expires_at, 1_000 + ONE_DAY);
    assert_eq!(client.get_delegation_count(&grantor), 1);
}

#[test]
fn is_delegation_active_reports_scope_precisely() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL));
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_ALL));
    // Unknown and empty scopes answer false rather than erroring, so a caller
    // can pre-flight without risking a reverted transaction.
    assert!(!client.is_delegation_active(&grantor, &delegate, &0));
    assert!(!client.is_delegation_active(&grantor, &delegate, &0xffff_ffff));
}

#[test]
fn a_grant_can_carry_several_scopes_at_once() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL));
}

#[test]
fn regranting_overwrites_without_consuming_another_slot() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);
    assert_eq!(client.get_delegation_count(&grantor), 1);

    // Narrow the scope and shorten the window on the same delegate.
    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &(ONE_DAY / 2),
    );

    assert_eq!(client.get_delegation_count(&grantor), 1);
    let record = client.get_delegation(&grantor, &delegate).unwrap();
    assert_eq!(record.scope, DELEGATION_SCOPE_REGISTER_SEAL);
    assert_eq!(record.expires_at, 1_000 + ONE_DAY / 2);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));
}

#[test]
#[should_panic(expected = "Error(Contract, #30)")] // SelfDelegation
fn a_grantor_cannot_delegate_to_itself() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &grantor,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")] // InvalidDelegationScope
fn a_zero_scope_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &0, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #24)")] // InvalidDelegationScope
fn an_unknown_scope_bit_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &(DELEGATION_SCOPE_REGISTER_SOURCE | 1 << 20),
        &ONE_DAY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")] // InvalidDelegationDuration
fn a_zero_duration_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #25)")] // InvalidDelegationDuration
fn a_duration_past_the_cap_is_rejected() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &(MAX_DELEGATION_DURATION_SECS + 1),
    );
}

#[test]
fn a_duration_exactly_at_the_cap_is_accepted() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let expires_at = client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &MAX_DELEGATION_DURATION_SECS,
    );

    assert_eq!(expires_at, 1_000 + MAX_DELEGATION_DURATION_SECS);
}

// ---------------------------------------------------------------------------
// Storage bounds
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #29)")] // DelegationsSaturated
fn a_grantor_cannot_exceed_the_delegate_cap() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    for _ in 0..MAX_DELEGATIONS_PER_GRANTOR {
        client.grant_delegation(
            &grantor,
            &Address::generate(&env),
            &DELEGATION_SCOPE_REGISTER_SOURCE,
            &ONE_DAY,
        );
    }
    assert_eq!(
        client.get_delegation_count(&grantor),
        MAX_DELEGATIONS_PER_GRANTOR
    );

    client.grant_delegation(
        &grantor,
        &Address::generate(&env),
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
}

#[test]
fn revoking_frees_a_slot() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    assert_eq!(client.get_delegation_count(&grantor), 1);

    client.revoke_delegation(&grantor, &grantor, &delegate);

    assert_eq!(client.get_delegation_count(&grantor), 0);
    assert_eq!(client.get_delegation(&grantor, &delegate), None);
}

#[test]
fn one_grantors_cap_does_not_affect_another() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let other_grantor = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    assert_eq!(client.get_delegation_count(&grantor), 1);
    assert_eq!(client.get_delegation_count(&other_grantor), 0);
    assert!(!client.is_delegation_active(
        &other_grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE
    ));
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn a_delegation_lapses_at_its_expiry_without_a_transaction() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    env.ledger().set_timestamp(1_000 + ONE_DAY - 1);
    assert!(client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));

    // `expires_at` itself is already outside the window.
    env.ledger().set_timestamp(1_000 + ONE_DAY);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_REGISTER_SOURCE));

    // The record remains readable so an operator can see and prune it.
    assert!(client.get_delegation(&grantor, &delegate).is_some());
}

#[test]
#[should_panic(expected = "Error(Contract, #27)")] // DelegationExpired
fn an_expired_delegation_cannot_register() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    env.ledger().set_timestamp(1_000 + ONE_DAY + 1);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Revocation authorization
// ---------------------------------------------------------------------------

#[test]
fn the_admin_can_revoke_a_delegation_it_did_not_grant() {
    let (env, contract_id, admin, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&admin, &grantor, &delegate);

    assert_eq!(client.get_delegation(&grantor, &delegate), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_stranger_cannot_revoke_a_delegation() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let stranger = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&stranger, &grantor, &delegate);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_revoke_its_own_delegation_on_the_grantors_behalf() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.revoke_delegation(&delegate, &grantor, &delegate);
}

#[test]
fn revoking_an_absent_delegation_is_a_no_op() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Idempotent: a retried or duplicated revocation converges rather than
    // erroring, and never drives the slot counter below zero.
    client.revoke_delegation(&grantor, &grantor, &delegate);
    client.revoke_delegation(&grantor, &grantor, &delegate);

    assert_eq!(client.get_delegation_count(&grantor), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_revoked_delegation_stops_working_immediately() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.revoke_delegation(&grantor, &grantor, &delegate);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Delegated registration — Tier 2
// ---------------------------------------------------------------------------

#[test]
fn a_delegate_registers_a_source_proof_attributed_to_the_grantor() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    let video_hash = b32(&env, 1);
    let proof_id = b32(&env, 3);
    let record = client.register_source_delegated(
        &delegate,
        &grantor,
        &video_hash,
        &b32(&env, 2),
        &proof_id,
    );

    // Authority is attributed to the grantor…
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.source, Some(grantor.clone()));
    assert_eq!(client.get_proof(&proof_id).unwrap().source, Some(grantor));
    assert_eq!(
        client.get_by_video(&video_hash).unwrap().video_hash,
        video_hash
    );

    // …while the history names the actor, so the two are never conflated.
    let entry = client.get_proof_history_at(&proof_id, &1).unwrap();
    assert_eq!(entry.action, ProofLifecycleAction::Registered as u32);
    assert_eq!(entry.actor, Some(delegate));
}

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_delegate_without_a_grant_cannot_register() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")] // DelegationScopeExceeded
fn a_seal_scoped_delegate_cannot_register_a_source_proof() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #21)")] // Paused
fn delegated_registration_respects_the_tier_2_pause() {
    let (env, contract_id, admin, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3_600);

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")] // DuplicateProof
fn delegated_registration_still_enforces_proof_uniqueness() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
    client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 9),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Delegated registration — Tier 3
// ---------------------------------------------------------------------------

#[test]
fn a_delegate_registers_a_seal_for_an_active_issuer() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    let proof_id = b32(&env, 3);
    let record =
        client.register_seal_delegated(&delegate, &issuer, &b32(&env, 1), &b32(&env, 2), &proof_id);

    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(issuer));
    assert_eq!(
        client.get_proof_history_at(&proof_id, &1).unwrap().actor,
        Some(delegate)
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn a_delegation_does_not_substitute_for_issuer_standing() {
    let (env, contract_id, _, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // The grantor delegates a seal scope but was never registered as an issuer.
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn revoking_the_issuer_stops_its_delegates_too() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );
    client.revoke_issuer(&admin, &issuer);

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #28)")] // DelegationScopeExceeded
fn a_source_scoped_delegate_cannot_register_a_seal() {
    let (env, contract_id, admin, issuer, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.add_issuer(&admin, &issuer, &b32(&env, 7));
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Non-transitivity and privilege containment
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #26)")] // DelegationNotFound
fn a_delegate_cannot_pass_the_grantors_authority_to_a_third_party() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let third_party = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    // The delegate can only ever grant its *own* authority. Even with auths
    // mocked, the resulting record is keyed (delegate -> third_party) and says
    // nothing about the original grantor.
    client.grant_delegation(
        &delegate,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    assert!(!client.is_delegation_active(
        &grantor,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE
    ));

    // So the third party cannot register for the original grantor.
    client.register_source_delegated(
        &third_party,
        &grantor,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

#[test]
fn a_second_hop_delegation_only_binds_its_own_grantor() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let third_party = Address::generate(&env);

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );
    client.grant_delegation(
        &delegate,
        &third_party,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_DAY,
    );

    // The second hop registers proofs attributed to the delegate, never to the
    // original grantor.
    let proof_id = b32(&env, 3);
    let record = client.register_source_delegated(
        &third_party,
        &delegate,
        &b32(&env, 1),
        &b32(&env, 2),
        &proof_id,
    );

    assert_eq!(record.source, Some(delegate));
    assert_ne!(record.source, Some(grantor));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_reach_admin_entry_points() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    // A maximally scoped delegation still confers nothing outside registration.
    client.add_issuer(&delegate, &delegate, &b32(&env, 7));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_revoke_a_proof() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);
    let proof_id = b32(&env, 3);
    client.register_source_delegated(&delegate, &grantor, &b32(&env, 1), &b32(&env, 2), &proof_id);

    client.revoke_proof(&delegate, &proof_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_delegate_cannot_pause_a_domain() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.grant_delegation(&grantor, &delegate, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    client.pause(&delegate, &PAUSE_DOMAIN_TIER2_REGISTRATION, &3_600);
}

#[test]
fn direct_registration_is_unaffected_by_the_delegation_feature() {
    let (env, contract_id, _, grantor, delegate) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Backwards compatibility: a source with no delegations at all still
    // registers exactly as before.
    let proof_id = b32(&env, 3);
    let record = client.register_source(&grantor, &b32(&env, 1), &b32(&env, 2), &proof_id);

    assert_eq!(record.source, Some(grantor.clone()));
    assert_eq!(client.get_delegation_count(&grantor), 0);
    assert!(!client.is_delegation_active(&grantor, &delegate, &DELEGATION_SCOPE_ALL));
    assert_eq!(
        client.get_proof_history_at(&proof_id, &1).unwrap().actor,
        Some(grantor)
    );
}

// ---------------------------------------------------------------------------
// Listing and pagination (#714)
// ---------------------------------------------------------------------------

#[test]
fn list_delegations_empty_when_no_grants() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let page = client.list_delegations(&grantor, &0, &10);
    assert_eq!(page.entries.len(), 0);
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.total, 0);
}

#[test]
fn list_delegations_matches_grants_after_grant_regrant_revoke() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let d1 = Address::generate(&env);
    let d2 = Address::generate(&env);
    let d3 = Address::generate(&env);

    client.grant_delegation(&grantor, &d1, &DELEGATION_SCOPE_REGISTER_SOURCE, &ONE_DAY);
    client.grant_delegation(&grantor, &d2, &DELEGATION_SCOPE_REGISTER_SEAL, &ONE_DAY);
    client.grant_delegation(&grantor, &d3, &DELEGATION_SCOPE_ALL, &ONE_DAY);

    assert_eq!(client.get_delegation_count(&grantor), 3);
    let page = client.list_delegations(&grantor, &0, &10);
    assert_eq!(page.entries.len(), 3);
    assert_eq!(page.total, 3);
    assert_eq!(page.next_cursor, None);

    // Re-grant d2 with modified scope and duration: does NOT duplicate index entry
    client.grant_delegation(&grantor, &d2, &DELEGATION_SCOPE_ALL, &(2 * ONE_DAY));
    assert_eq!(client.get_delegation_count(&grantor), 3);
    let page2 = client.list_delegations(&grantor, &0, &10);
    assert_eq!(page2.entries.len(), 3);
    assert_eq!(page2.total, 3);

    // Verify d2 has updated record
    let mut found_d2 = false;
    for entry in page2.entries.iter() {
        if entry.delegate == d2 {
            found_d2 = true;
            assert_eq!(entry.record.scope, DELEGATION_SCOPE_ALL);
            assert_eq!(entry.record.expires_at, 1_000 + 2 * ONE_DAY);
        }
    }
    assert!(found_d2);

    // Revoke d1 (slot reuse test: d3 is swapped into slot 0)
    client.revoke_delegation(&grantor, &grantor, &d1);
    assert_eq!(client.get_delegation_count(&grantor), 2);

    let page3 = client.list_delegations(&grantor, &0, &10);
    assert_eq!(page3.entries.len(), 2);
    assert_eq!(page3.total, 2);

    let mut delegates = std::vec::Vec::new();
    for entry in page3.entries.iter() {
        delegates.push(entry.delegate.clone());
    }
    assert!(delegates.contains(&d2));
    assert!(delegates.contains(&d3));
    assert!(!delegates.contains(&d1));

    // Can grant a new delegate into the freed slot
    let d4 = Address::generate(&env);
    client.grant_delegation(&grantor, &d4, &DELEGATION_SCOPE_REGISTER_SOURCE, &ONE_DAY);
    assert_eq!(client.get_delegation_count(&grantor), 3);
    let page4 = client.list_delegations(&grantor, &0, &10);
    assert_eq!(page4.entries.len(), 3);
    assert_eq!(page4.total, 3);
}

#[test]
fn list_delegations_pagination_and_limits() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let mut delegates = std::vec::Vec::new();
    for _ in 0..5 {
        let d = Address::generate(&env);
        client.grant_delegation(&grantor, &d, &DELEGATION_SCOPE_REGISTER_SOURCE, &ONE_DAY);
        delegates.push(d);
    }
    assert_eq!(client.get_delegation_count(&grantor), 5);

    // Page 1: limit 2
    let p1 = client.list_delegations(&grantor, &0, &2);
    assert_eq!(p1.entries.len(), 2);
    assert_eq!(p1.next_cursor, Some(2));
    assert_eq!(p1.total, 5);

    // Page 2: limit 2
    let p2 = client.list_delegations(&grantor, &p1.next_cursor.unwrap(), &2);
    assert_eq!(p2.entries.len(), 2);
    assert_eq!(p2.next_cursor, Some(4));
    assert_eq!(p2.total, 5);

    // Page 3: limit 2 -> remaining 1 entry
    let p3 = client.list_delegations(&grantor, &p2.next_cursor.unwrap(), &2);
    assert_eq!(p3.entries.len(), 1);
    assert_eq!(p3.next_cursor, None);
    assert_eq!(p3.total, 5);

    // Out-of-bounds cursor
    let p4 = client.list_delegations(&grantor, &10, &2);
    assert_eq!(p4.entries.len(), 0);
    assert_eq!(p4.next_cursor, None);
    assert_eq!(p4.total, 5);

    // Zero limit is capped to MAX_DELEGATIONS_PER_GRANTOR
    let p_default = client.list_delegations(&grantor, &0, &0);
    assert_eq!(p_default.entries.len(), 5);
    assert_eq!(p_default.next_cursor, None);
    assert_eq!(p_default.total, 5);
}

#[test]
fn property_model_test_delegation_sequences() {
    let (env, contract_id, _, grantor, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Reference model: Vec of (delegate address, (scope, duration))
    let mut model: std::vec::Vec<(Address, (u32, u64))> = std::vec::Vec::new();

    let mut pool = std::vec::Vec::new();
    for _ in 0..12 {
        pool.push(Address::generate(&env));
    }

    // Pseudo-random deterministic sequence of operations
    let ops = [
        (0, 0, 1, 100), // Grant pool[0]
        (0, 1, 2, 200), // Grant pool[1]
        (0, 2, 3, 300), // Grant pool[2]
        (0, 0, 2, 500), // Re-grant pool[0]
        (1, 1, 0, 0),   // Revoke pool[1]
        (0, 3, 1, 400), // Grant pool[3]
        (0, 4, 2, 150), // Grant pool[4]
        (1, 0, 0, 0),   // Revoke pool[0]
        (0, 5, 3, 600), // Grant pool[5]
        (0, 1, 1, 700), // Re-grant pool[1] (was revoked, becomes new grant)
        (1, 2, 0, 0),   // Revoke pool[2]
        (0, 6, 2, 800), // Grant pool[6]
        (1, 9, 0, 0),   // Revoke pool[9] (not in model, no-op)
    ];

    for (op, pool_idx, scope, duration) in ops.iter() {
        let delegate = &pool[*pool_idx];
        if *op == 0 {
            // Grant / regrant
            client.grant_delegation(&grantor, delegate, scope, duration);
            if let Some(pos) = model.iter().position(|(d, _)| d == delegate) {
                model[pos] = (delegate.clone(), (*scope, *duration));
            } else {
                model.push((delegate.clone(), (*scope, *duration)));
            }
        } else {
            // Revoke
            client.revoke_delegation(&grantor, &grantor, delegate);
            if let Some(pos) = model.iter().position(|(d, _)| d == delegate) {
                model.remove(pos);
            }
        }

        // Compare contract listing with reference model
        assert_eq!(client.get_delegation_count(&grantor), model.len() as u32);
        let page = client.list_delegations(&grantor, &0, &MAX_DELEGATIONS_PER_GRANTOR);
        assert_eq!(page.entries.len(), model.len() as u32);
        assert_eq!(page.total, model.len() as u32);

        let mut listed = std::vec::Vec::new();
        for entry in page.entries.iter() {
            listed.push((entry.delegate.clone(), entry.record.scope));
        }

        for (delegate, (expected_scope, _)) in model.iter() {
            let found = listed.iter().find(|(d, _)| d == delegate);
            assert!(
                found.is_some(),
                "Delegate in model must exist in contract listing"
            );
            assert_eq!(
                found.unwrap().1,
                *expected_scope,
                "Delegate scope in listing must match model"
            );
        }
    }
}

