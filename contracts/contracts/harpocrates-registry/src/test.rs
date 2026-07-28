#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _},
    Address, Bytes, Env,
};

#[contract]
struct MockNoirVerifier;

#[contractimpl]
impl MockNoirVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        // 5 public inputs × 32 bytes = 160 bytes (after domain separation)
        if public_inputs.len() != 160 || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn proof_bytes(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

fn silent_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
    domain_tag: &BytesN<32>,
) -> Bytes {
    let mut video_hash_bytes = [0u8; 32];
    video_hash.copy_into_slice(&mut video_hash_bytes);

    let mut credential_root_bytes = [0u8; 32];
    credential_root.copy_into_slice(&mut credential_root_bytes);

    let mut nullifier_bytes = [0u8; 32];
    nullifier.copy_into_slice(&mut nullifier_bytes);

    let mut domain_tag_bytes = [0u8; 32];
    domain_tag.copy_into_slice(&mut domain_tag_bytes);

    // 5 public inputs × 32 bytes = 160 bytes
    let mut bytes = [0u8; 160];
    bytes[16..32].copy_from_slice(&video_hash_bytes[..16]);
    bytes[48..64].copy_from_slice(&video_hash_bytes[16..]);
    bytes[64..96].copy_from_slice(&credential_root_bytes);
    bytes[96..128].copy_from_slice(&nullifier_bytes);
    bytes[128..160].copy_from_slice(&domain_tag_bytes);

    Bytes::from_array(env, &bytes)
}

fn expected_domain_tag_test(env: &Env) -> BytesN<32> {
    // Compute SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD)
    // This mirrors the registry contract's expected_domain_tag() function.
    let protocol: [u8; 32] = [
        0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae,
        0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10, 0xd5,
        0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1,
        0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71, 0xc2, 0x1,
    ];
    let version: [u8; 32] = [
        0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0,
        0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9, 0xdd,
        0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94,
        0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a, 0xc6, 0x23,
    ];
    let network: [u8; 32] = [
        0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f,
        0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5, 0xf5,
        0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82,
        0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77, 0xa5, 0xf,
    ];
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&protocol);
    preimage.extend_from_array(&version);
    preimage.extend_from_array(&network);
    env.crypto().sha256(&preimage).into()
}

#[test]
fn registers_all_identity_tiers() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &bytes32(&env, 9));
    client.add_credential_root(&admin, &bytes32(&env, 5), &bytes32(&env, 10));

    let anonymous = client.register_anonymous(
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &bytes32(&env, 3),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
    assert_eq!(anonymous.tier, TIER_SILENT_WITNESS);
    assert_eq!(anonymous.nullifier, Some(bytes32(&env, 4)));
    assert!(client.has_nullifier(&bytes32(&env, 4)));

    let pseudonymous = client.register_source(
        &source,
        &bytes32(&env, 11),
        &bytes32(&env, 12),
        &bytes32(&env, 13),
    );
    assert_eq!(pseudonymous.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(pseudonymous.source, Some(source));

    let sealed = client.register_seal(
        &issuer,
        &bytes32(&env, 21),
        &bytes32(&env, 22),
        &bytes32(&env, 23),
    );
    assert_eq!(sealed.tier, TIER_PUBLIC_SEAL);
    assert_eq!(sealed.issuer, Some(issuer));
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn rejects_reused_nullifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init(&admin);
    client.add_credential_root(&admin, &bytes32(&env, 5), &bytes32(&env, 10));
    client.register_anonymous(
        &bytes32(&env, 1),
        &bytes32(&env, 2),
        &bytes32(&env, 3),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
    client.register_anonymous(
        &bytes32(&env, 6),
        &bytes32(&env, 7),
        &bytes32(&env, 8),
        &bytes32(&env, 4),
        &bytes32(&env, 5),
        &proof_bytes(&env),
    );
}

#[test]
fn can_lookup_by_video_hash() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let video_hash = bytes32(&env, 31);

    client.init(&admin);
    client.register_source(&source, &video_hash, &bytes32(&env, 32), &bytes32(&env, 33));

    let record = client.get_by_video(&video_hash).unwrap();
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.status, STATUS_REGISTERED);
}

#[test]
fn registers_silent_witness_through_external_verifier() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 41);
    let credential_root = bytes32(&env, 9);
    let nullifier = bytes32(&env, 42);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 45));
    assert_eq!(client.get_verifier(), Some(verifier_id));
    assert!(client.get_credential_root(&credential_root).unwrap().active);

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 43),
        &bytes32(&env, 44),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &expected_domain_tag_test(&env)),
        &proof_bytes(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
    assert_eq!(record.nullifier, Some(nullifier.clone()));
    assert!(client.has_nullifier(&nullifier));
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn rejects_revoked_silent_witness_credential_root() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 51);
    let credential_root = bytes32(&env, 52);
    let nullifier = bytes32(&env, 53);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 54));
    client.revoke_credential_root(&admin, &credential_root);

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 55),
        &bytes32(&env, 56),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &expected_domain_tag_test(&env)),
        &proof_bytes(&env),
    );
}

#[test]
fn transfers_admin_after_proposal_is_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &new_admin);
    assert_eq!(env.events().all().events().len(), 1);
    client.accept_admin(&new_admin);
    assert_eq!(env.events().all().events().len(), 1);

    client.add_issuer(&new_admin, &issuer, &bytes32(&env, 61));
    assert!(client.get_issuer(&issuer).unwrap().active);
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn cancelled_admin_transfer_cannot_be_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_transfer(&admin);
    assert_eq!(env.events().all().events().len(), 1);
    client.accept_admin(&pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn replaced_admin_proposal_cannot_be_accepted() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let first_pending_admin = Address::generate(&env);
    let replacement_pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &first_pending_admin);
    client.propose_admin(&admin, &replacement_pending_admin);
    client.accept_admin(&first_pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_admin_cannot_propose_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let pending_admin = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&unauthorized, &pending_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_pending_admin_cannot_accept_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.accept_admin(&unauthorized);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn non_admin_cannot_cancel_admin_transfer() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let pending_admin = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    client.init(&admin);
    client.propose_admin(&admin, &pending_admin);
    client.cancel_admin_transfer(&unauthorized);
}

// ── Domain separation tests (NEW) ────────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn rejects_wrong_domain_tag() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 71);
    let credential_root = bytes32(&env, 72);
    let nullifier = bytes32(&env, 73);
    let wrong_tag = bytes32(&env, 99); // wrong — must equal expected_domain_tag

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 74));

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 75),
        &bytes32(&env, 76),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &wrong_tag),
        &proof_bytes(&env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn rejects_zero_domain_tag() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 81);
    let credential_root = bytes32(&env, 82);
    let nullifier = bytes32(&env, 83);
    let zero_tag = BytesN::from_array(&env, &[0u8; 32]);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 84));

    client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 85),
        &bytes32(&env, 86),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &zero_tag),
        &proof_bytes(&env),
    );
}

#[test]
fn accepts_correct_domain_tag() {
    // Positive: providing the correct domain tag allows registration.
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockNoirVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = bytes32(&env, 91);
    let credential_root = bytes32(&env, 92);
    let nullifier = bytes32(&env, 93);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &bytes32(&env, 94));

    let record = client.register_anonymous_verified(
        &video_hash,
        &bytes32(&env, 95),
        &bytes32(&env, 96),
        &silent_public_inputs(&env, &video_hash, &credential_root, &nullifier, &expected_domain_tag_test(&env)),
        &proof_bytes(&env),
    );

    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.video_hash, video_hash);
}
