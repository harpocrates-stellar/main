//! Verifier circuit-version validation (#343) and bounded delegated expiry
//! (#338).
//!
//! Rules under test:
//!
//! 1. Every verified entry point validates the proof's circuit version at the
//!    trust boundary *before* the external verifier is invoked, so a proof the
//!    verifier cannot answer fails closed with the stable
//!    `UnsupportedCircuitVersion` code.
//! 2. The supported window defaults to the full built-in range, so existing
//!    deployments and stored evidence validate exactly as before.
//! 3. The window is admin-only, additive, and bounded by what this wasm build
//!    can actually frame; empty or out-of-range windows are rejected.
//! 4. A delegated registration never produces a proof that outlives the
//!    delegation that authorized it (#338).

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger},
    xdr::ContractEventBody,
    Address, Bytes, BytesN, Env, Symbol, TryFromVal,
};

/// Accepts any non-empty proof so the test isolates the version boundary.
#[contract]
struct MockAcceptingVerifier;

#[contractimpl]
impl MockAcceptingVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        if public_inputs.is_empty() || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

/// Rejects every proof. Used to prove the version check runs *before* the
/// external call: a version-window rejection must not surface as `InvalidProof`.
#[contract]
struct MockRejectingVerifier;

#[contractimpl]
impl MockRejectingVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {
        panic!("verifier must not be reached")
    }
}

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn one_day() -> u64 {
    24 * 60 * 60
}

// ---------------------------------------------------------------------------
// Selective-disclosure frame builder (352 bytes; carries a circuit_version).
// ---------------------------------------------------------------------------

fn copy_field(bytes: &mut [u8; 352], pos: &mut usize, src: &BytesN<32>) {
    let mut arr = [0u8; 32];
    src.copy_into_slice(&mut arr);
    bytes[*pos..*pos + 32].copy_from_slice(&arr);
    *pos += 32;
}

fn selective_disclosure_inputs(
    env: &Env,
    schema_hash: &BytesN<32>,
    issuer_namespace: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    circuit_version: u32,
) -> Bytes {
    let mut bytes = [0u8; 352];
    let mut pos: usize = 0;
    copy_field(&mut bytes, &mut pos, schema_hash);
    copy_field(&mut bytes, &mut pos, issuer_namespace);
    bytes[92..96].copy_from_slice(&1u32.to_be_bytes()); // schema_version
    pos += 32;
    copy_field(&mut bytes, &mut pos, credential_root);
    copy_field(&mut bytes, &mut pos, nullifier);
    copy_field(&mut bytes, &mut pos, &b32(env, 0xAA)); // video_hash_hi
    copy_field(&mut bytes, &mut pos, &b32(env, 0xAB)); // video_hash_lo
    copy_field(&mut bytes, &mut pos, &b32(env, 0xBB)); // verifier_digest
    bytes[284..288].copy_from_slice(&circuit_version.to_be_bytes());
    pos += 32;
    copy_field(&mut bytes, &mut pos, &b32(env, 0xCC)); // evidence_digest
    copy_field(&mut bytes, &mut pos, &b32(env, 0xDD)); // predicate_commitment
    Bytes::from_array(env, &bytes)
}

/// Fresh registry with a verifier configured, all within one `Env`.
fn setup(accepting: bool) -> (Env, Address, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let verifier = if accepting {
        env.register(MockAcceptingVerifier, ())
    } else {
        env.register(MockRejectingVerifier, ())
    };
    client.set_verifier(&admin, &verifier);
    (env, contract_id, client, admin)
}

/// Configure a schema + credential root and return (schema_hash, credential_root).
fn seed_selective_disclosure(
    env: &Env,
    client: &HarpocratesRegistryClient,
    admin: &Address,
) -> (BytesN<32>, BytesN<32>) {
    let schema_hash = b32(env, 0x01);
    let namespace = b32(env, 0x02);
    let credential_root = b32(env, 0xAA);
    client.add_schema(admin, &schema_hash, &namespace, &1, &3);
    client.add_credential_root(admin, &credential_root, &b32(env, 0xDD));
    (schema_hash, credential_root)
}

fn has_event(env: &Env, contract_id: &Address, t0: &str, t1: &str) -> bool {
    for event in env.events().all().filter_by_contract(contract_id).events() {
        let topics = match &event.body {
            ContractEventBody::V0(v0) => &v0.topics,
        };
        if topics.len() < 2 {
            continue;
        }
        let first = Symbol::try_from_val(env, topics.get(0).unwrap()).ok();
        let second = Symbol::try_from_val(env, topics.get(1).unwrap()).ok();
        if first == Some(Symbol::new(env, t0)) && second == Some(Symbol::new(env, t1)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Defaults and read-only pre-flight
// ---------------------------------------------------------------------------

#[test]
fn version_window_defaults_to_the_full_builtin_range() {
    let (_, _, client, _) = setup(true);
    let window = client.get_verifier_circuit_versions();
    assert_eq!(window.min_version, MIN_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(window.max_version, MAX_SUPPORTED_CIRCUIT_VERSION);

    // Both built-in versions are accepted; anything outside is not.
    assert!(client.is_supported_circuit_version(&MIN_SUPPORTED_CIRCUIT_VERSION));
    assert!(client.is_supported_circuit_version(&MAX_SUPPORTED_CIRCUIT_VERSION));
    assert!(!client.is_supported_circuit_version(&0));
    assert!(!client.is_supported_circuit_version(&(MAX_SUPPORTED_CIRCUIT_VERSION + 1)));
}

#[test]
fn supported_version_constants_are_consistent() {
    // The implicit versions are read off the existing codec boundaries, not
    // invented here.
    assert_eq!(CIRCUIT_VERSION_SILENT_WITNESS_V1, MIN_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(CIRCUIT_VERSION_SILENT_WITNESS_V2, MAX_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(
        CIRCUIT_VERSION_SELECTIVE_DISCLOSURE,
        CURRENT_SELECTIVE_DISCLOSURE_VERSION
    );
    assert_eq!(CIRCUIT_VERSION_REVOCATION_WITNESS, 1);
    assert_eq!(CIRCUIT_VERSION_AGGREGATION, 1);
}

// ---------------------------------------------------------------------------
// Authorization and input validation
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn non_admin_cannot_set_the_version_window() {
    let (env, _, client, _) = setup(true);
    let stranger = Address::generate(&env);
    client.set_verifier_circuit_versions(&stranger, &1, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #80)")] // InvalidCircuitVersionRange
fn an_empty_version_window_is_rejected() {
    let (_, _, client, admin) = setup(true);
    client.set_verifier_circuit_versions(&admin, &2, &1);
}

#[test]
#[should_panic(expected = "Error(Contract, #80)")] // InvalidCircuitVersionRange
fn a_window_below_the_wasm_range_is_rejected() {
    let (_, _, client, admin) = setup(true);
    client.set_verifier_circuit_versions(&admin, &0, &2);
}

#[test]
#[should_panic(expected = "Error(Contract, #80)")] // InvalidCircuitVersionRange
fn a_window_above_the_wasm_range_is_rejected() {
    let (_, _, client, admin) = setup(true);
    client.set_verifier_circuit_versions(&admin, &1, &3);
}

// ---------------------------------------------------------------------------
// Boundary: the window is enforced at the trust boundary
// ---------------------------------------------------------------------------

#[test]
fn exact_min_equals_max_window_is_accepted() {
    let (env, _, client, admin) = setup(true);
    let (schema_hash, credential_root) = seed_selective_disclosure(&env, &client, &admin);

    client.set_verifier_circuit_versions(&admin, &1, &1);
    let window = client.get_verifier_circuit_versions();
    assert_eq!((window.min_version, window.max_version), (1, 1));

    let inputs = selective_disclosure_inputs(
        &env,
        &schema_hash,
        &b32(&env, 0x02),
        &credential_root,
        &b32(&env, 0xBB),
        1,
    );
    client.verify_selective_disclosure(&inputs, &Bytes::from_array(&env, &[1, 2, 3, 4]));
    assert!(client.has_nullifier(&b32(&env, 0xBB)));
}

#[test]
#[should_panic(expected = "Error(Contract, #79)")] // UnsupportedCircuitVersion
fn a_version_outside_the_window_is_rejected() {
    let (env, _, client, admin) = setup(false);
    let (schema_hash, credential_root) = seed_selective_disclosure(&env, &client, &admin);

    // Declare a window that excludes the v1 selective-disclosure circuit.
    client.set_verifier_circuit_versions(&admin, &2, &2);

    let inputs = selective_disclosure_inputs(
        &env,
        &schema_hash,
        &b32(&env, 0x02),
        &credential_root,
        &b32(&env, 0xBB),
        1,
    );
    // The rejecting verifier would surface #7 (InvalidProof) if it were reached;
    // #79 proves the version gate runs first.
    client.verify_selective_disclosure(&inputs, &Bytes::from_array(&env, &[1, 2, 3, 4]));
}

#[test]
fn widening_the_window_restores_acceptance() {
    let (env, _, client, admin) = setup(true);
    let (schema_hash, credential_root) = seed_selective_disclosure(&env, &client, &admin);

    client.set_verifier_circuit_versions(&admin, &2, &2);
    assert!(!client.is_supported_circuit_version(&1));

    client.set_verifier_circuit_versions(&admin, &1, &2);
    assert!(client.is_supported_circuit_version(&1));

    let inputs = selective_disclosure_inputs(
        &env,
        &schema_hash,
        &b32(&env, 0x02),
        &credential_root,
        &b32(&env, 0xBB),
        1,
    );
    client.verify_selective_disclosure(&inputs, &Bytes::from_array(&env, &[1, 2, 3, 4]));
}

#[test]
fn setting_the_window_emits_a_version_only_event() {
    let (env, contract_id, client, admin) = setup(true);
    client.set_verifier_circuit_versions(&admin, &1, &2);
    assert!(has_event(&env, &contract_id, "verif", "versions"));
}

#[test]
fn configuring_a_new_verifier_resets_the_window_to_default() {
    let (env, _, client, admin) = setup(true);

    client.set_verifier_circuit_versions(&admin, &2, &2);
    assert_eq!(client.get_verifier_circuit_versions().min_version, 2);

    let replacement = env.register(MockAcceptingVerifier, ());
    client.set_verifier(&admin, &replacement);

    let window = client.get_verifier_circuit_versions();
    assert_eq!(window.min_version, MIN_SUPPORTED_CIRCUIT_VERSION);
    assert_eq!(window.max_version, MAX_SUPPORTED_CIRCUIT_VERSION);
}

// ---------------------------------------------------------------------------
// #338 — delegated registration never outlives its delegation
// ---------------------------------------------------------------------------

fn delegation_setup() -> (Env, HarpocratesRegistryClient<'static>, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let grantor = Address::generate(&env);
    let delegate = Address::generate(&env);
    client.init(&admin);
    (env, client, admin, grantor, delegate)
}

#[test]
fn delegated_source_proof_is_bounded_by_the_delegation() {
    let (env, client, _, grantor, delegate) = delegation_setup();

    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &one_day(),
    );

    let record = client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 0x01),
        &b32(&env, 0x02),
        &b32(&env, 0x03),
    );

    // Default TTL is eternal (0), but a delegated proof must not outlive the
    // authority that created it.
    assert_eq!(record.expires_at, 1_000 + one_day());
    assert_ne!(record.expires_at, 0);
}

#[test]
fn delegated_issuer_seal_is_bounded_by_the_delegation() {
    let (env, client, admin, issuer, delegate) = delegation_setup();
    client.add_issuer(&admin, &issuer, &b32(&env, 0x07));

    client.grant_delegation(&issuer, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL, &one_day());

    let record = client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 0x11),
        &b32(&env, 0x12),
        &b32(&env, 0x13),
    );

    assert_eq!(record.expires_at, 1_000 + one_day());
}

#[test]
fn a_shorter_proof_ttl_still_wins_over_the_delegation() {
    let (env, client, admin, grantor, delegate) = delegation_setup();

    client.set_proof_ttl(&admin, &10);
    client.grant_delegation(
        &grantor,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &one_day(),
    );

    let record = client.register_source_delegated(
        &delegate,
        &grantor,
        &b32(&env, 0x21),
        &b32(&env, 0x22),
        &b32(&env, 0x23),
    );

    assert_eq!(record.expires_at, 1_000 + 10);
}

#[test]
fn direct_registration_is_unaffected_by_the_delegation_bound() {
    let (env, client, _, source, _) = delegation_setup();

    let record = client.register_source(
        &source,
        &b32(&env, 0x31),
        &b32(&env, 0x32),
        &b32(&env, 0x33),
    );

    // No delegation in play: the pre-#338 semantics are preserved exactly.
    assert_eq!(record.expires_at, 0);
}
