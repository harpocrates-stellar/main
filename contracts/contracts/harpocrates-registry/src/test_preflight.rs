//! Focused coverage for read-only statement registration preflight (#1199).
//!
//! Verifies:
//! 1. Public-field structural validation (`verifier_inputs`) across Tier 1
//!    `silent_witness/v1` (160B), `silent_witness/v2` (256B), and browser v1
//!    (128B) frames plus proof-blob size bounds (`64..=65536`).
//! 2. Active registry policy validation across initialization, per-tier pause
//!    domains, metadata envelope versions, statement uniqueness, credential
//!    root standing, scope epochs, nullifier replay, verifier configuration,
//!    circuit-version windows, Tier 3 role/issuer standing, and windowed quotas.
//! 3. Strict separation between preflight acceptance (`preflight_accepted`) and
//!    cryptographic verification (`cryptographically_verified == false`,
//!    `proof_stored == false`, `requires_crypto_verify == true`,
//!    `stage == PreflightStage::StructureAndPolicyOnly`), with zero storage
//!    writes, zero quota consumption, zero events, and zero verifier calls.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger as _},
    Address, Bytes, BytesN, Env,
};

/// External verifier double that panics unconditionally if invoked.
///
/// Installing this verifier proves `preflight_statement` never invokes
/// `verify_proof` on the external verifier, while `register_anonymous_verified`
/// invokes it and fails closed with `RegistryError::InvalidProof` (#7).
#[contract]
struct PanickingVerifier;

#[contractimpl]
impl PanickingVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("external verifier must never be called during preflight");
    }
}

/// Accepting external verifier double for setting up real registrations in
/// duplicate / replay / quota tests.
#[contract]
struct AcceptingVerifier;

#[contractimpl]
impl AcceptingVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if !matches!(len, 128 | 160 | 256) || proof.is_empty() {
            panic!("invalid proof material");
        }
    }
}

fn b32(env: &Env, byte: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[31] = byte;
    BytesN::from_array(env, &arr)
}

fn video_hash_sample(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = seed.wrapping_add(i as u8);
    }
    BytesN::from_array(env, &arr)
}

fn build_v1_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let vh = video_hash.to_array();
    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&credential_root.to_array());
    buf[96..128].copy_from_slice(&nullifier.to_array());
    buf[128..160].copy_from_slice(&expected_domain_tag(env).to_array());
    Bytes::from_array(env, &buf)
}

fn build_browser_v1_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let vh = video_hash.to_array();
    let mut buf = [0u8; 128];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&credential_root.to_array());
    buf[96..128].copy_from_slice(&nullifier.to_array());
    Bytes::from_array(env, &buf)
}

fn build_v2_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    scope: &BytesN<32>,
    epoch: u64,
    circuit_version_trailer: u32,
) -> Bytes {
    let vh = video_hash.to_array();
    let mut buf = [0u8; 256];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&credential_root.to_array());
    buf[96..128].copy_from_slice(&nullifier.to_array());
    buf[128..160].copy_from_slice(&scope.to_array());
    buf[184..192].copy_from_slice(&epoch.to_be_bytes());
    buf[192..224].copy_from_slice(&expected_domain_tag(env).to_array());
    buf[252..256].copy_from_slice(&circuit_version_trailer.to_be_bytes());
    Bytes::from_array(env, &buf)
}

fn assert_preflight_invariants(res: &StatementPreflightResult) {
    assert!(
        !res.cryptographically_verified,
        "preflight must NEVER claim cryptographic verification"
    );
    assert!(!res.proof_stored, "preflight must NEVER store a proof");
    assert!(
        res.requires_crypto_verify,
        "preflight must always report that cryptographic verification is still required"
    );
    assert_eq!(res.stage, PreflightStage::StructureAndPolicyOnly);
}

#[test]
fn preflight_separates_acceptance_from_cryptographic_verification_and_stores_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let panicking_verifier = env.register(PanickingVerifier, ());

    let admin = Address::generate(&env);
    let root = b32(&env, 0x11);
    client.init(&admin);
    client.set_verifier(&admin, &panicking_verifier);
    client.add_credential_root(&admin, &root, &b32(&env, 0x99));

    // 1. V1 (160-byte) statement preflight succeeds even though PanickingVerifier
    //    panics if called, proving external proof verification is NOT executed.
    let vh_v1 = video_hash_sample(&env, 0x10);
    let meta = b32(&env, 0x20);
    let pid_v1 = b32(&env, 0x30);
    let null_v1 = b32(&env, 0x40);
    let pi_v1 = build_v1_inputs(&env, &vh_v1, &root, &null_v1);

    let res_v1 = client.preflight_statement(
        &vh_v1,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid_v1,
        &pi_v1,
        &verifier_inputs::MIN_PROOF_BYTES,
    );
    assert!(env.events().all().events().is_empty());
    assert_preflight_invariants(&res_v1);
    assert!(res_v1.preflight_accepted);
    assert_eq!(res_v1.registry_error_code, 0);
    assert_eq!(res_v1.codec_reject_code, verifier_inputs::ACCEPTED_CODE);
    assert_eq!(res_v1.tier, TIER_SILENT_WITNESS);
    assert_eq!(res_v1.circuit_version, CIRCUIT_VERSION_SILENT_WITNESS_V1);
    assert_eq!(res_v1.envelope_version, METADATA_ENVELOPE_V1);

    // Repeat identical preflight to prove idempotence (nothing stored or consumed).
    let res_v1_repeat = client.preflight_statement(
        &vh_v1,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid_v1,
        &pi_v1,
        &verifier_inputs::MAX_PROOF_BYTES,
    );
    assert_eq!(res_v1_repeat, res_v1);
    assert_eq!(client.get_proof(&pid_v1), None);
    assert_eq!(client.get_by_video(&vh_v1), None);
    assert!(!client.has_nullifier(&panicking_verifier, &null_v1));
    assert_eq!(client.get_proof_history_count(&pid_v1), 0);

    // 2. V2 (256-byte) statement preflight with METADATA_ENVELOPE_V2.
    let vh_v2 = video_hash_sample(&env, 0x50);
    let pid_v2 = b32(&env, 0x51);
    let null_v2 = b32(&env, 0x52);
    let scope = b32(&env, 0x53);
    client.set_scope_epoch(&admin, &scope, &3);
    let pi_v2 = build_v2_inputs(
        &env,
        &vh_v2,
        &root,
        &null_v2,
        &scope,
        3,
        verifier_inputs::EXPECTED_CIRCUIT_VERSION,
    );

    let res_v2 =
        client.preflight_statement(&vh_v2, &meta, &METADATA_ENVELOPE_V2, &pid_v2, &pi_v2, &256);
    assert!(env.events().all().events().is_empty());
    assert_preflight_invariants(&res_v2);
    assert!(res_v2.preflight_accepted);
    assert_eq!(res_v2.circuit_version, CIRCUIT_VERSION_SILENT_WITNESS_V2);
    assert_eq!(res_v2.envelope_version, METADATA_ENVELOPE_V2);

    // 3. Browser V1 (128-byte) statement preflight.
    let vh_br = video_hash_sample(&env, 0x60);
    let pid_br = b32(&env, 0x61);
    let null_br = b32(&env, 0x62);
    let pi_br = build_browser_v1_inputs(&env, &vh_br, &root, &null_br);
    let res_br =
        client.preflight_statement(&vh_br, &meta, &METADATA_ENVELOPE_V1, &pid_br, &pi_br, &128);
    assert!(env.events().all().events().is_empty());
    assert_preflight_invariants(&res_br);
    assert!(res_br.preflight_accepted);
    assert_eq!(res_br.circuit_version, CIRCUIT_VERSION_SILENT_WITNESS_V1);

    // 4. Actual registration with synthetic/unverified proof bytes invokes
    //    PanickingVerifier and fails closed with InvalidProof (#7), proving
    //    cryptographic verification remains mandatory at registration time.
    let fake_proof = Bytes::from_array(&env, &[0xAA; 64]);
    let reg_attempt =
        client.try_register_anonymous_verified(&vh_v1, &meta, &pid_v1, &pi_v1, &fake_proof);
    assert_eq!(
        reg_attempt.err(),
        Some(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::InvalidProof as u32
        )))
    );
    assert_eq!(client.get_proof(&pid_v1), None);
}

#[test]
fn preflight_rejects_public_field_structure_and_proof_bound_violations() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let verifier = env.register(AcceptingVerifier, ());
    let admin = Address::generate(&env);
    let root = b32(&env, 0x07);

    client.init(&admin);
    client.set_verifier(&admin, &verifier);
    client.add_credential_root(&admin, &root, &b32(&env, 0x08));

    let vh = video_hash_sample(&env, 0x22);
    let meta = b32(&env, 0x23);
    let pid = b32(&env, 0x24);
    let nullifier = b32(&env, 0x25);
    let scope = b32(&env, 0x26);

    // Wrong frame length (96 bytes).
    let short_frame = Bytes::from_array(&env, &[0u8; 96]);
    let res =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &short_frame, &128);
    assert_preflight_invariants(&res);
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::Length.as_code());

    // Superseded bare 224-byte v2 frame -> CircuitVersionMismatch (#87) + Length (#2).
    let bare_v2 = Bytes::from_array(&env, &[0u8; 224]);
    let res = client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &bare_v2, &128);
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::CircuitVersionMismatch as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::Length.as_code());

    // V2 wrong circuit-version trailer -> CircuitVersionMismatch (#87) + VersionMismatch (#10).
    let wrong_ver = build_v2_inputs(&env, &vh, &root, &nullifier, &scope, 0, 1);
    let res = client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &wrong_ver, &128);
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::CircuitVersionMismatch as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::VersionMismatch.as_code());

    // Dirty 128-bit half padding -> InvalidPublicInputs (#10) + Padding (#3).
    let valid_v1 = build_v1_inputs(&env, &vh, &root, &nullifier);
    let mut dirty_pad = [0u8; 160];
    valid_v1.copy_into_slice(&mut dirty_pad);
    dirty_pad[0] = 0x01;
    let res = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &Bytes::from_array(&env, &dirty_pad),
        &128,
    );
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::Padding.as_code());

    // Non-canonical BN254 field (>= modulus) -> InvalidPublicInputs (#10) + NonCanonicalField (#4).
    let mut non_canon = [0u8; 160];
    valid_v1.copy_into_slice(&mut non_canon);
    non_canon[64..96].copy_from_slice(&verifier_inputs::BN254_SCALAR_FIELD_MODULUS_BE);
    let res = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &Bytes::from_array(&env, &non_canon),
        &128,
    );
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(
        res.codec_reject_code,
        RejectCode::NonCanonicalField.as_code()
    );

    // Zero nullifier -> InvalidPublicInputs (#10) + ZeroField (#5).
    let mut zero_null = [0u8; 160];
    valid_v1.copy_into_slice(&mut zero_null);
    zero_null[96..128].fill(0);
    let res = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &Bytes::from_array(&env, &zero_null),
        &128,
    );
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::ZeroField.as_code());

    // Domain tag mismatch -> DomainTagMismatch (#49) + DomainMismatch (#6).
    let mut bad_domain = [0u8; 160];
    valid_v1.copy_into_slice(&mut bad_domain);
    bad_domain[159] ^= 0x01;
    let res = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &Bytes::from_array(&env, &bad_domain),
        &128,
    );
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::DomainTagMismatch as u32
    );
    assert_eq!(res.codec_reject_code, RejectCode::DomainMismatch.as_code());

    // Reconstructed video_hash mismatch against statement video_hash -> InvalidPublicInputs (#10).
    let other_vh = video_hash_sample(&env, 0x99);
    let res = client.preflight_statement(
        &other_vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &valid_v1,
        &128,
    );
    assert!(!res.preflight_accepted);
    assert_eq!(
        res.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );
    assert_eq!(res.codec_reject_code, verifier_inputs::ACCEPTED_CODE);

    // Proof undersize (63 bytes) & oversize (65537 bytes) -> InvalidProof (#7) + ProofUndersize/ProofOversize.
    let undersize = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &valid_v1,
        &(verifier_inputs::MIN_PROOF_BYTES - 1),
    );
    assert!(!undersize.preflight_accepted);
    assert_eq!(
        undersize.registry_error_code,
        RegistryError::InvalidProof as u32
    );
    assert_eq!(
        undersize.codec_reject_code,
        RejectCode::ProofUndersize.as_code()
    );

    let oversize = client.preflight_statement(
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
        &valid_v1,
        &(verifier_inputs::MAX_PROOF_BYTES + 1),
    );
    assert!(!oversize.preflight_accepted);
    assert_eq!(
        oversize.registry_error_code,
        RegistryError::InvalidProof as u32
    );
    assert_eq!(
        oversize.codec_reject_code,
        RejectCode::ProofOversize.as_code()
    );
}

#[test]
fn preflight_enforces_active_tier1_policy_boundaries() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let vh = video_hash_sample(&env, 0x31);
    let meta = b32(&env, 0x32);
    let zero_meta = BytesN::from_array(&env, &[0u8; 32]);
    let pid = b32(&env, 0x33);
    let root = b32(&env, 0x34);
    let nullifier = b32(&env, 0x35);
    let scope = b32(&env, 0x36);
    let pi_v1 = build_v1_inputs(&env, &vh, &root, &nullifier);

    // 1. Uninitialized registry -> NotInitialized (#2).
    let uninit = client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert_preflight_invariants(&uninit);
    assert!(!uninit.preflight_accepted);
    assert_eq!(
        uninit.registry_error_code,
        RegistryError::NotInitialized as u32
    );

    let admin = Address::generate(&env);
    client.init(&admin);

    // 2. UnknownCredentialRoot (#11) before credential root is registered.
    let unknown_root =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert!(!unknown_root.preflight_accepted);
    assert_eq!(
        unknown_root.registry_error_code,
        RegistryError::UnknownCredentialRoot as u32
    );

    client.add_credential_root(&admin, &root, &meta);

    // 3. VerifierNotSet (#9) before set_verifier.
    let no_verif =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert!(!no_verif.preflight_accepted);
    assert_eq!(
        no_verif.registry_error_code,
        RegistryError::VerifierNotSet as u32
    );

    let verifier = env.register(AcceptingVerifier, ());
    client.set_verifier(&admin, &verifier);

    // 4. Envelope policy: version 0 or > max -> UnsupportedMetadataEnvelopeVersion (#68);
    //    V2 with zero metadata_hash -> InvalidMetadataEnvelope (#69).
    let bad_env_zero = client.preflight_statement(&vh, &meta, &0, &pid, &pi_v1, &128);
    assert_eq!(
        bad_env_zero.registry_error_code,
        RegistryError::UnsupportedMetadataEnvelopeVersion as u32
    );
    let bad_env_high = client.preflight_statement(&vh, &meta, &99, &pid, &pi_v1, &128);
    assert_eq!(
        bad_env_high.registry_error_code,
        RegistryError::UnsupportedMetadataEnvelopeVersion as u32
    );
    let zero_v2 =
        client.preflight_statement(&vh, &zero_meta, &METADATA_ENVELOPE_V2, &pid, &pi_v1, &128);
    assert_eq!(
        zero_v2.registry_error_code,
        RegistryError::InvalidMetadataEnvelope as u32
    );

    // 5. Pause policy & domain isolation: pausing Tier 2 leaves Tier 1 accepted;
    //    pausing Tier 1 rejects with Paused (#21) until auto-expiry.
    client.pause(&admin, &PAUSE_DOMAIN_TIER2_REGISTRATION, &300);
    assert!(
        client
            .preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128)
            .preflight_accepted
    );

    client.pause(&admin, &PAUSE_DOMAIN_TIER1_REGISTRATION, &120);
    let paused = client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert!(!paused.preflight_accepted);
    assert_eq!(paused.registry_error_code, RegistryError::Paused as u32);

    // Advance past Tier 1 pause expiry -> automatically accepted again.
    env.ledger().set_timestamp(10_120);
    assert!(
        client
            .preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128)
            .preflight_accepted
    );
    client.unpause(&admin, &PAUSE_DOMAIN_ALL_REGISTRATION);

    // 6. Verifier circuit-version window: narrowing to 2..=2 rejects v1 (#81) and accepts v2.
    client.set_verifier_circuit_versions(&admin, &2, &2);
    let unsup_v1 =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert!(!unsup_v1.preflight_accepted);
    assert_eq!(
        unsup_v1.registry_error_code,
        RegistryError::UnsupportedCircuitVersion as u32
    );

    let pi_v2 = build_v2_inputs(
        &env,
        &vh,
        &root,
        &nullifier,
        &scope,
        0,
        verifier_inputs::EXPECTED_CIRCUIT_VERSION,
    );
    assert!(
        client
            .preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v2, &128)
            .preflight_accepted
    );

    // Restore full 1..=2 window.
    client.set_verifier_circuit_versions(
        &admin,
        &MIN_SUPPORTED_CIRCUIT_VERSION,
        &MAX_SUPPORTED_CIRCUIT_VERSION,
    );

    // 7. Scoped epoch mismatch -> StaleEpoch (#53).
    client.set_scope_epoch(&admin, &scope, &1);
    let stale = client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v2, &128);
    assert!(!stale.preflight_accepted);
    assert_eq!(stale.registry_error_code, RegistryError::StaleEpoch as u32);

    // 8. Register the v1 proof for real, then verify DuplicateProof (#4),
    //    DuplicateVideo (#5), and DuplicateNullifier (#6).
    let proof_bytes = Bytes::from_array(&env, &[0xBB; 64]);
    client.register_anonymous_verified(&vh, &meta, &pid, &pi_v1, &proof_bytes);

    let dup_proof =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &pid, &pi_v1, &128);
    assert_eq!(
        dup_proof.registry_error_code,
        RegistryError::DuplicateProof as u32
    );

    let fresh_pid = b32(&env, 0x77);
    let dup_video =
        client.preflight_statement(&vh, &meta, &METADATA_ENVELOPE_V1, &fresh_pid, &pi_v1, &128);
    assert_eq!(
        dup_video.registry_error_code,
        RegistryError::DuplicateVideo as u32
    );

    let fresh_vh = video_hash_sample(&env, 0x88);
    let replayed_null_pi = build_v1_inputs(&env, &fresh_vh, &root, &nullifier);
    let dup_null = client.preflight_statement(
        &fresh_vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &fresh_pid,
        &replayed_null_pi,
        &128,
    );
    assert_eq!(
        dup_null.registry_error_code,
        RegistryError::DuplicateNullifier as u32
    );

    // 9. Credential root expiry (#92) and revocation (#12).
    let root_exp = b32(&env, 0x91);
    client.add_credential_root(&admin, &root_exp, &meta);
    client.expire_credential_root(&admin, &root_exp);
    let pi_exp = build_v1_inputs(&env, &fresh_vh, &root_exp, &b32(&env, 0x92));
    let expired_res = client.preflight_statement(
        &fresh_vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &fresh_pid,
        &pi_exp,
        &128,
    );
    assert_eq!(
        expired_res.registry_error_code,
        RegistryError::ExpiredCredentialRoot as u32
    );

    client.revoke_credential_root(&admin, &root);
    let pi_rev = build_v1_inputs(&env, &fresh_vh, &root, &b32(&env, 0x93));
    let revoked_res = client.preflight_statement(
        &fresh_vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &fresh_pid,
        &pi_rev,
        &128,
    );
    assert_eq!(
        revoked_res.registry_error_code,
        RegistryError::RevokedCredentialRoot as u32
    );
}

#[test]
fn preflight_tier_statement_enforces_tier2_and_tier3_policies_without_charging_quota_or_auth() {
    let env = Env::default();
    env.ledger().set_timestamp(60_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    let replacement_issuer = Address::generate(&env);
    let unknown_actor = Address::generate(&env);

    let vh = video_hash_sample(&env, 0xA1);
    let meta = b32(&env, 0xA2);
    let pid = b32(&env, 0xA3);

    // Unauthenticated preflight before init -> NotInitialized (#2), invalid tier -> InvalidPublicInputs (#10).
    let bad_tier = client.preflight_tier_statement(
        &TIER_SILENT_WITNESS,
        &source,
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
    );
    assert_preflight_invariants(&bad_tier);
    assert!(!bad_tier.preflight_accepted);
    assert_eq!(
        bad_tier.registry_error_code,
        RegistryError::InvalidPublicInputs as u32
    );

    let uninit = client.preflight_tier_statement(
        &TIER_CONSISTENT_SOURCE,
        &source,
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
    );
    assert_eq!(
        uninit.registry_error_code,
        RegistryError::NotInitialized as u32
    );

    // Setup admin, active issuer, and 1-per-60s quotas using mocked auths, then clear mock auths!
    env.mock_all_auths();
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &meta);
    client.add_issuer(&admin, &replacement_issuer, &meta);
    client.set_issuer_quota(&admin, &source, &1, &60);
    client.set_issuer_quota(&admin, &issuer, &1, &60);
    env.set_auths(&[]);

    // Without ANY auth signature, both Tier 2 and Tier 3 preflight succeed,
    // emit zero events, and leave quota usage at 0 across repeated calls!
    for _ in 0..3 {
        let t2 = client.preflight_tier_statement(
            &TIER_CONSISTENT_SOURCE,
            &source,
            &vh,
            &meta,
            &METADATA_ENVELOPE_V1,
            &pid,
        );
        assert!(env.events().all().events().is_empty());
        assert_preflight_invariants(&t2);
        assert!(t2.preflight_accepted);
        assert_eq!(t2.tier, TIER_CONSISTENT_SOURCE);

        let t3 = client.preflight_tier_statement(
            &TIER_PUBLIC_SEAL,
            &issuer,
            &vh,
            &meta,
            &METADATA_ENVELOPE_V2,
            &pid,
        );
        assert!(env.events().all().events().is_empty());
        assert_preflight_invariants(&t3);
        assert!(t3.preflight_accepted);
        assert_eq!(t3.tier, TIER_PUBLIC_SEAL);
    }
    assert_eq!(client.get_issuer_quota_usage(&source).count, 0);
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 0);
    assert_eq!(client.get_proof(&pid), None);

    // Real registration without auth MUST still fail (proving signature verification is separate).
    assert!(client
        .try_register_source(&source, &vh, &meta, &pid)
        .is_err());

    // RoleConflict (#92) when admin attempts Tier 3 seal preflight.
    let role_conflict = client.preflight_tier_statement(
        &TIER_PUBLIC_SEAL,
        &admin,
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
    );
    assert_eq!(
        role_conflict.registry_error_code,
        RegistryError::RoleConflict as u32
    );

    // UnknownIssuer (#8) for unapproved address.
    let unknown_iss = client.preflight_tier_statement(
        &TIER_PUBLIC_SEAL,
        &unknown_actor,
        &vh,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid,
    );
    assert_eq!(
        unknown_iss.registry_error_code,
        RegistryError::UnknownIssuer as u32
    );

    // Consume source's 1-registration quota via real registration -> preflight reports IssuerQuotaExhausted (#93).
    env.mock_all_auths();
    client.register_source(&source, &vh, &meta, &pid);

    let vh2 = video_hash_sample(&env, 0xB1);
    let pid2 = b32(&env, 0xB2);
    let exhausted = client.preflight_tier_statement(
        &TIER_CONSISTENT_SOURCE,
        &source,
        &vh2,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid2,
    );
    assert!(!exhausted.preflight_accepted);
    assert_eq!(
        exhausted.registry_error_code,
        RegistryError::IssuerQuotaExhausted as u32
    );

    // Roll forward into next 60s window bucket -> quota resets lazily without write!
    env.ledger().set_timestamp(60_060);
    let rolled = client.preflight_tier_statement(
        &TIER_CONSISTENT_SOURCE,
        &source,
        &vh2,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid2,
    );
    assert!(rolled.preflight_accepted);

    // Rotating out an issuer keeps historical evidence verifiable during grace
    // (`is_issuer_verifiable == true`), while `preflight_tier_statement` rejects
    // *new* Tier 3 seal statements from the retired key with UnknownIssuer (#8)!
    client.rotate_issuer(&admin, &issuer, &replacement_issuer, &0);
    assert!(client.is_issuer_verifiable(&issuer));
    let retired_seal = client.preflight_tier_statement(
        &TIER_PUBLIC_SEAL,
        &issuer,
        &vh2,
        &meta,
        &METADATA_ENVELOPE_V1,
        &pid2,
    );
    assert!(!retired_seal.preflight_accepted);
    assert_eq!(
        retired_seal.registry_error_code,
        RegistryError::UnknownIssuer as u32
    );
}
