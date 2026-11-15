//! Canonical public role-policy digest tests (#1192).
//!
//! Uses synthetic addresses and hashes only — no real media, witness values,
//! credentials, or private keys are present.

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[test]
fn equivalent_policy_states_across_permuted_signers_versions_and_roundtrips_match() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);

    // Shared synthetic actors deployed in the same Env so addresses match across
    // two independent HarpocratesRegistry instances.
    let admin = Address::generate(&env);
    let temp_guardian = Address::generate(&env);
    let temp_pending = Address::generate(&env);
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    let m1 = Address::generate(&env);
    let m2 = Address::generate(&env);
    let m3 = Address::generate(&env);

    let id_a = env.register(HarpocratesRegistry, ());
    let id_b = env.register(HarpocratesRegistry, ());
    let client_a = HarpocratesRegistryClient::new(&env, &id_a);
    let client_b = HarpocratesRegistryClient::new(&env, &id_b);

    client_a.init(&admin);
    client_b.init(&admin);

    // Baseline digests match immediately after init.
    let init_a = client_a.get_role_policy_digest();
    let init_b = client_b.get_role_policy_digest();
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(init_a.encoding_version, ROLE_POLICY_DIGEST_V1);
    assert_eq!(init_a, init_b);

    // Registry A goes through churn that converges to the same effective policy:
    // - explicit default timelock delay
    // - set + clear guardian
    // - propose + cancel admin transfer
    // - pause + unpause domain
    // - cancelled seal policy v1, then v2 with [s1, s2, s3] followed by removing s3
    // - active council with [m1, m2, m3]
    client_a.set_timelock_min_delay_secs(&admin, &DEFAULT_TIMELOCK_MIN_DELAY_SECS);
    client_a.set_guardian(&admin, &temp_guardian);
    client_a.clear_guardian(&admin);
    client_a.propose_admin(&admin, &temp_pending);
    client_a.cancel_admin_transfer(&admin);
    client_a.pause(&admin, &PAUSE_DOMAIN_TIER3_REGISTRATION, &120);
    client_a.unpause(&admin, &PAUSE_DOMAIN_TIER3_REGISTRATION);

    client_a.add_issuer(&admin, &s1, &b32(&env, 0x11));
    client_a.add_issuer(&admin, &s2, &b32(&env, 0x12));
    client_a.add_issuer(&admin, &s3, &b32(&env, 0x13));
    let v1_a = client_a.create_seal_policy(&admin, &1, &2, &300, &0);
    client_a.cancel_seal_policy(&admin, &v1_a);
    let v2_a = client_a.create_seal_policy(&admin, &2, &4, &600, &0);
    client_a.add_seal_policy_signer(&admin, &v2_a, &s1);
    client_a.add_seal_policy_signer(&admin, &v2_a, &s2);
    client_a.add_seal_policy_signer(&admin, &v2_a, &s3);
    client_a.remove_seal_policy_signer(&admin, &v2_a, &s3);

    let mut council_a = Vec::new(&env);
    council_a.push_back(m1.clone());
    council_a.push_back(m2.clone());
    council_a.push_back(m3.clone());
    client_a.set_admin_council(&admin, &council_a, &2);

    // Registry B configures the equivalent effective policy directly at a later
    // timestamp with reversed seal signers [s2, s1] and permuted council [m3, m1, m2].
    env.ledger().set_timestamp(10_500);
    client_b.add_issuer(&admin, &s2, &b32(&env, 0x22));
    client_b.add_issuer(&admin, &s1, &b32(&env, 0x21));
    let v1_b = client_b.create_seal_policy(&admin, &2, &4, &600, &0);
    client_b.add_seal_policy_signer(&admin, &v1_b, &s2);
    client_b.add_seal_policy_signer(&admin, &v1_b, &s1);

    let mut council_b = Vec::new(&env);
    council_b.push_back(m3.clone());
    council_b.push_back(m1.clone());
    council_b.push_back(m2.clone());
    client_b.set_admin_council(&admin, &council_b, &2);

    // Advance past council activation delay for both registries.
    env.ledger()
        .set_timestamp(10_500 + DEFAULT_TIMELOCK_MIN_DELAY_SECS + 10);

    let final_a = client_a.get_role_policy_digest();
    let final_b = client_b.get_role_policy_digest();
    assert!(final_a.council_active);
    assert!(final_a.seal_policy_active);
    assert_eq!(final_a, final_b);
    assert!(client_b.verify_role_policy_digest(&ROLE_POLICY_DIGEST_V1, &final_a.digest));
}

#[test]
fn digest_changes_on_every_bounded_policy_dimension_and_fails_closed_on_version() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(20_000);

    let id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    let guardian = Address::generate(&env);
    let pending = Address::generate(&env);
    let signer = Address::generate(&env);

    client.init(&admin);
    let base = client.get_role_policy_digest();

    // Unsupported encoding versions fail closed even with matching digest bytes.
    assert!(!client.verify_role_policy_digest(&0, &base.digest));
    assert!(!client.verify_role_policy_digest(&2, &base.digest));
    assert!(client.verify_role_policy_digest(&ROLE_POLICY_DIGEST_V1, &base.digest));

    // Guardian changes digest.
    client.set_guardian(&admin, &guardian);
    let with_guardian = client.get_role_policy_digest();
    assert!(with_guardian.has_guardian);
    assert_ne!(with_guardian.digest, base.digest);

    // Pause changes digest, and natural pause expiry restores previous digest!
    let pause_exp = client.pause(&guardian, &PAUSE_DOMAIN_TIER1_REGISTRATION, &60);
    let paused = client.get_role_policy_digest();
    assert_eq!(paused.paused_domains, PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert_ne!(paused.digest, with_guardian.digest);

    env.ledger().set_timestamp(pause_exp + 1);
    let post_pause = client.get_role_policy_digest();
    assert_eq!(post_pause, with_guardian);

    // Pending admin changes digest.
    client.propose_admin(&admin, &pending);
    let with_pending = client.get_role_policy_digest();
    assert_ne!(with_pending.digest, post_pause.digest);

    // Timelock delay changes digest.
    client.set_timelock_min_delay_secs(&admin, &3_600);
    let with_delay = client.get_role_policy_digest();
    assert_ne!(with_delay.digest, with_pending.digest);

    // Seal policy + active signer changes digest; revoking the signer updates
    // the effective signer set in the digest immediately.
    client.add_issuer(&admin, &signer, &b32(&env, 0x77));
    let ver = client.create_seal_policy(&admin, &1, &2, &300, &0);
    client.add_seal_policy_signer(&admin, &ver, &signer);
    let with_seal = client.get_role_policy_digest();
    assert!(with_seal.seal_policy_active);
    assert_ne!(with_seal.digest, with_delay.digest);

    client.revoke_issuer(&admin, &signer);
    let after_revoke = client.get_role_policy_digest();
    assert_ne!(after_revoke.digest, with_seal.digest);
}
