//! Signed receipt digest commitment (#337).
//!
//! The registry stores only `sha256(canonical_json(signed_receipt))` — never
//! the receipt itself. A receipt-signing key (admin-managed allowlist)
//! attests to that digest with a P-256 signature over a domain-separated,
//! contract-bound preimage:
//!
//! ```text
//! sha256(RECEIPT_ATTEST_DOMAIN || ScAddress-XDR(contract) || proof_id
//!        || receipt_digest)
//! ```
//!
//! Signature vectors below were generated OFFLINE (Node.js ECDSA over the
//! raw 32-byte prehash, IEEE-P1363 encoding — matching the host's
//! `verify_prehash`) for the fixed contract id used by `env::register_at`.
//! No private key is committed; the keypair was discarded after signing.
//!
//! Fixed contract id `acb6183a…b1730` → `CCWLMGB2F6O6VG7BQHKDUUL4R2WOAZ62TGOMU2TESZOKGBO6PMLTANC3`
//! (second id `8d72630d…2bf3d` is only used to prove contract binding).

#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::xdr::ToXdr;
use std::format;
use std::string::ToString;

pub(crate) const CONTRACT1_STRKEY: &str =
    "CCWLMGB2F6O6VG7BQHKDUUL4R2WOAZ62TGOMU2TESZOKGBO6PMLTANC3";
const CONTRACT1_ID: [u8; 32] = [
    0xac, 0xb6, 0x18, 0x3a, 0x2f, 0x9d, 0xea, 0x9b, 0xe1, 0x81, 0xd4, 0x3a, 0x51, 0x7c, 0x8e, 0xac,
    0xe0, 0x67, 0xda, 0x99, 0x9c, 0xca, 0x6a, 0x64, 0x96, 0x5c, 0xa3, 0x05, 0xde, 0x7b, 0x17, 0x30,
];

pub(crate) const PUB1: [u8; 65] = [
    0x04, 0x06, 0xa9, 0x27, 0xe2, 0x78, 0x33, 0x0b, 0x67, 0x67, 0x26, 0xe2, 0x8b, 0x72, 0x0b, 0xd7,
    0x62, 0xec, 0xde, 0x7b, 0xbf, 0x3a, 0x36, 0x10, 0x97, 0xb5, 0xc0, 0xff, 0x51, 0x74, 0xe7, 0x3b,
    0xfb, 0x4a, 0x5e, 0x90, 0x38, 0xdb, 0x56, 0xea, 0x13, 0xcc, 0x89, 0x17, 0x87, 0x17, 0xd0, 0x76,
    0xce, 0x50, 0xc5, 0xd2, 0x85, 0x31, 0xa0, 0xcf, 0x4f, 0xf0, 0x20, 0xe2, 0xa3, 0x5c, 0xb5, 0xbb,
    0xc7,
];
const PUB2: [u8; 65] = [
    0x04, 0x12, 0x39, 0x7b, 0xef, 0x52, 0xe6, 0x56, 0x99, 0x85, 0x74, 0xab, 0xab, 0xff, 0x5c, 0xaf,
    0xc0, 0x81, 0xe8, 0xb3, 0x63, 0x79, 0xdc, 0x9b, 0x8a, 0x61, 0x88, 0x10, 0x8c, 0x49, 0x5b, 0x01,
    0xea, 0x80, 0xea, 0xd9, 0xce, 0x84, 0x86, 0x89, 0xd9, 0xb8, 0xa3, 0x69, 0x36, 0x23, 0x7d, 0xc5,
    0x4f, 0x10, 0x4d, 0xda, 0x63, 0x46, 0x82, 0xb6, 0x52, 0x34, 0x5a, 0xf6, 0x07, 0x34, 0x3f, 0x04,
    0x0b,
];
pub(crate) const DIGEST1: [u8; 32] = [
    0xcf, 0x29, 0x43, 0x6e, 0x41, 0x03, 0xb0, 0xdd, 0xc6, 0x26, 0x22, 0x9c, 0xe2, 0xc7, 0x94, 0x5c,
    0xa4, 0xc3, 0xfb, 0xea, 0x2b, 0x6f, 0x31, 0x02, 0x21, 0x16, 0x4d, 0x32, 0x1d, 0xd9, 0x96, 0xde,
];
const DIGEST2: [u8; 32] = [
    0xf0, 0xdb, 0x4a, 0xcc, 0xc6, 0xa6, 0x74, 0x94, 0x30, 0x39, 0xf6, 0xea, 0xec, 0x2c, 0xed, 0x88,
    0x36, 0xea, 0x32, 0x46, 0x92, 0xf6, 0x40, 0xf4, 0xd2, 0xec, 0xf8, 0x9a, 0x3d, 0xbd, 0xe6, 0x83,
];
/// Valid for (contract1, proof `[0x11; 32]`, DIGEST1).
pub(crate) const SIG_A: [u8; 64] = [
    0x9d, 0x26, 0x9c, 0xc3, 0xa7, 0xd2, 0xa8, 0xc6, 0x45, 0x61, 0xfe, 0x94, 0xaa, 0xba, 0x47, 0x8c,
    0x13, 0xb6, 0xa2, 0x86, 0xef, 0xb3, 0x3d, 0x26, 0xbb, 0x30, 0x23, 0x86, 0xd4, 0xc5, 0x7f, 0x43,
    0x5d, 0xd4, 0x6d, 0x17, 0x31, 0x38, 0x4b, 0x20, 0x19, 0x44, 0x19, 0x55, 0xdd, 0x84, 0x3c, 0x6f,
    0xfd, 0x3f, 0xeb, 0xf4, 0xb3, 0x18, 0x97, 0xaa, 0x6c, 0x7b, 0xac, 0xb4, 0xb3, 0xc8, 0x12, 0x53,
];
/// Valid for (contract1, proof `[0x22; 32]`, DIGEST1).
const SIG_B: [u8; 64] = [
    0x71, 0x99, 0xb1, 0x21, 0x3d, 0xbb, 0x72, 0x58, 0xb2, 0xef, 0xd7, 0xff, 0xe9, 0xe7, 0xbd, 0x06,
    0xdf, 0xba, 0xd5, 0xa6, 0x47, 0x2e, 0x28, 0xf3, 0x92, 0xc1, 0xca, 0x5a, 0x32, 0x98, 0x0d, 0xbc,
    0x30, 0xa1, 0x63, 0x07, 0x34, 0x1e, 0xc1, 0x81, 0xe6, 0x63, 0xfe, 0x7b, 0xfc, 0xf8, 0x8f, 0x27,
    0x01, 0x26, 0xc8, 0xaa, 0xc8, 0xee, 0xc5, 0x99, 0x64, 0xa5, 0x8c, 0xf0, 0xf4, 0x31, 0xc4, 0xa7,
];
/// Valid for (contract1, proof `[0x33; 32]`, DIGEST1).
const SIG_C: [u8; 64] = [
    0x62, 0x2d, 0xdb, 0x6d, 0xb4, 0x1d, 0x92, 0x50, 0xd0, 0x07, 0xc5, 0x72, 0xc7, 0x9f, 0x1c, 0x0a,
    0x47, 0x77, 0x29, 0xe1, 0xd5, 0x3a, 0xae, 0xd5, 0x3d, 0x6e, 0x31, 0xc2, 0x85, 0xd5, 0xc8, 0x89,
    0x03, 0xe8, 0x8c, 0x29, 0x67, 0xf8, 0x2f, 0x5f, 0x2d, 0xeb, 0x14, 0xfb, 0x36, 0x9d, 0xca, 0x5c,
    0xe3, 0x91, 0xc7, 0x4a, 0xc1, 0x00, 0x87, 0xe7, 0x6a, 0x95, 0x03, 0xfe, 0x74, 0xaa, 0x76, 0x5f,
];
/// Valid for (contract1, proof `[0x11; 32]`, DIGEST2).
const SIG_D2: [u8; 64] = [
    0x81, 0x03, 0x31, 0x86, 0x23, 0x9e, 0xd6, 0x73, 0x95, 0xfd, 0x5d, 0x94, 0xb4, 0xf9, 0x49, 0x33,
    0x9b, 0xd9, 0x37, 0x61, 0x04, 0x6c, 0x19, 0xd6, 0x1d, 0x19, 0xbc, 0x22, 0x75, 0xe9, 0xbe, 0x86,
    0x61, 0xd4, 0x69, 0xb7, 0xa7, 0xbd, 0x1f, 0x81, 0x3b, 0x8e, 0x17, 0x3e, 0x73, 0xf9, 0x80, 0x62,
    0xe9, 0x97, 0x52, 0xbc, 0xc7, 0x72, 0xfd, 0xb5, 0x3a, 0xb3, 0x93, 0x54, 0xfb, 0xc6, 0xaa, 0xdb,
];
/// Valid for (contract2 `8d72630d…`, proof `[0x11; 32]`, DIGEST1) — used to
/// prove the attestation is contract-bound.
const SIG_C2: [u8; 64] = [
    0x1a, 0xbd, 0x7b, 0x9f, 0x5f, 0x63, 0xc8, 0xc6, 0x38, 0x87, 0x5d, 0x00, 0x19, 0xb2, 0x10, 0xa5,
    0xca, 0x7f, 0x47, 0x5b, 0x00, 0x2e, 0x75, 0x53, 0x8f, 0xce, 0xb6, 0x9b, 0x82, 0x9e, 0x18, 0x70,
    0x2f, 0x50, 0x38, 0xa7, 0x27, 0x78, 0xac, 0x2a, 0x76, 0x09, 0x2b, 0x7b, 0x93, 0x16, 0x26, 0x38,
    0xed, 0x85, 0xfe, 0xd2, 0x22, 0x63, 0x50, 0x6d, 0x03, 0xad, 0x25, 0xe9, 0x05, 0x2c, 0x25, 0xfb,
];
/// SIG_A with one byte flipped — must fail verification deterministically.
const SIG_BAD: [u8; 64] = [
    0x9d, 0x26, 0x9c, 0xc3, 0xa7, 0x2d, 0xa8, 0xc6, 0x45, 0x61, 0xfe, 0x94, 0xaa, 0xba, 0x47, 0x8c,
    0x13, 0xb6, 0xa2, 0x86, 0xef, 0xb3, 0x3d, 0x26, 0xbb, 0x30, 0x23, 0x86, 0xd4, 0xc5, 0x7f, 0x43,
    0x5d, 0xd4, 0x6d, 0x17, 0x31, 0x38, 0x4b, 0x20, 0x19, 0x44, 0x19, 0x55, 0xdd, 0x84, 0x3c, 0x6f,
    0xfd, 0x3f, 0xeb, 0xf4, 0xb3, 0x18, 0x97, 0xaa, 0x6c, 0x7b, 0xac, 0xb4, 0xb3, 0xc8, 0x12, 0x53,
];

const COMMITTED_AT: u64 = 1_700_000_000;
const PROOF1: u8 = 0x11;
const PROOF2: u8 = 0x22;
const PROOF3: u8 = 0x33;

#[contract]
struct MockReceiptVerifier;

#[contractimpl]
impl MockReceiptVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if !(matches!(len, 128 | 160 | 224)) || proof.is_empty() {
            panic!("invalid receipt test proof");
        }
    }
}

struct Fixture {
    env: Env,
    client: HarpocratesRegistryClient<'static>,
    admin: Address,
}

fn b32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

fn pk1(env: &Env) -> BytesN<65> {
    BytesN::from_array(env, &PUB1)
}

fn digest1(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &DIGEST1)
}

fn sig_a(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &SIG_A)
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(COMMITTED_AT);

    let contract_address =
        Address::from_string(&soroban_sdk::String::from_str(&env, CONTRACT1_STRKEY));
    let contract_id = env.register_at(&contract_address, HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    Fixture { env, client, admin }
}

/// Register a tier-2 proof whose id is `[proof_byte; 32]` and return the source.
fn register_tier2(f: &Fixture, proof_byte: u8, video_byte: u8) -> Address {
    let source = Address::generate(&f.env);
    f.client.register_source(
        &source,
        &b32(&f.env, video_byte),
        &b32(&f.env, video_byte + 1),
        &b32(&f.env, proof_byte),
    );
    source
}

/// Register a tier-3 proof whose id is `[proof_byte; 32]` and return the issuer.
fn register_tier3(f: &Fixture, proof_byte: u8, video_byte: u8) -> Address {
    let issuer = Address::generate(&f.env);
    f.client.add_issuer(&f.admin, &issuer, &b32(&f.env, 0x09));
    f.client.register_seal(
        &issuer,
        &b32(&f.env, video_byte),
        &b32(&f.env, video_byte + 1),
        &b32(&f.env, proof_byte),
    );
    issuer
}

/// Register a full tier-1 (silent witness) proof with external verification.
fn register_tier1(f: &Fixture, proof_byte: u8, video_byte: u8) {
    let verifier = f.env.register(MockReceiptVerifier, ());
    f.client.set_verifier(&f.admin, &verifier);
    let credential_root = b32(&f.env, 0x09);
    f.client
        .add_credential_root(&f.admin, &credential_root, &b32(&f.env, 0x45));

    let video_hash = b32(&f.env, video_byte);
    let mut video_hash_bytes = [0u8; 32];
    video_hash.copy_into_slice(&mut video_hash_bytes);
    let mut root_bytes = [0u8; 32];
    credential_root.copy_into_slice(&mut root_bytes);
    let mut nullifier = [0u8; 32];
    b32(&f.env, 0x42).copy_into_slice(&mut nullifier);
    let mut domain = [0u8; 32];
    expected_domain_tag(&f.env).copy_into_slice(&mut domain);

    // 5 public inputs x 32 bytes = 160 bytes (v1 silent witness frame).
    let mut bytes = [0u8; 160];
    bytes[16..32].copy_from_slice(&video_hash_bytes[..16]);
    bytes[48..64].copy_from_slice(&video_hash_bytes[16..]);
    bytes[64..96].copy_from_slice(&root_bytes);
    bytes[96..128].copy_from_slice(&nullifier);
    bytes[128..160].copy_from_slice(&domain);

    let record = f.client.register_anonymous_verified(
        &video_hash,
        &b32(&f.env, video_byte + 1),
        &b32(&f.env, proof_byte),
        &Bytes::from_array(&f.env, &bytes),
        &Bytes::from_array(&f.env, &[1, 2, 3, 4]),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
}

fn commit_events(f: &Fixture) -> u32 {
    event_test_utils::count_events(&f.env, &["receipt", "commit"])
}

fn add_events(f: &Fixture) -> u32 {
    event_test_utils::count_events(&f.env, &["signer", "add"])
}

fn revoke_events(f: &Fixture) -> u32 {
    event_test_utils::count_events(&f.env, &["signer", "revoke"])
}

// ---------------------------------------------------------------------------
// Attestation preimage layout
// ---------------------------------------------------------------------------

/// The attestation binds the 36-byte ScAddress XDR (4-byte discriminant 1 ||
/// 32-byte contract id), not the 40-byte ScVal envelope `Address::to_xdr`
/// produces. Pin the layout the offline vectors were signed over.
#[test]
fn receipt_attestation_preimage_binds_scaddress_xdr() {
    let env = Env::default();
    let addr = Address::from_string(&soroban_sdk::String::from_str(&env, CONTRACT1_STRKEY));
    let xdr: Bytes = addr.to_xdr(&env);
    assert_eq!(xdr.len(), 40);

    let scaddr = xdr.slice(4..40);
    let mut buf = [0u8; 36];
    scaddr.copy_into_slice(&mut buf);
    assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
    assert_eq!(&buf[4..], &CONTRACT1_ID[..]);

    // domain (29) || ScAddress (36) || proof_id (32) || receipt_digest (32)
    assert_eq!(RECEIPT_ATTEST_PREIMAGE_LEN, 29 + 36 + 32 + 32);
}

// ---------------------------------------------------------------------------
// Commit happy paths
// ---------------------------------------------------------------------------

#[test]
fn receipt_commit_by_tier2_source() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let record = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );

    assert_eq!(record.proof_id, b32(&f.env, PROOF1));
    assert_eq!(record.receipt_digest, digest1(&f.env));
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(record.public_key, pk1(&f.env));
    assert_eq!(record.committed_by, source);
    assert_eq!(record.committed_at, COMMITTED_AT);
    assert_eq!(commit_events(&f), 1);

    let stored = f.client.get_receipt_commitment(&b32(&f.env, PROOF1));
    let stored = stored.unwrap();
    assert_eq!(stored.receipt_digest, digest1(&f.env));
    assert_eq!(stored.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(stored.public_key, pk1(&f.env));
    assert_eq!(stored.committed_by, source);
    assert_eq!(stored.committed_at, COMMITTED_AT);
}

#[test]
fn receipt_commit_by_tier3_issuer() {
    let f = fixture();
    let issuer = register_tier3(&f, PROOF2, 0x11);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let record = f.client.commit_receipt_digest(
        &issuer,
        &b32(&f.env, PROOF2),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_B),
    );
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.committed_by, issuer);
    assert_eq!(commit_events(&f), 1);
}

#[test]
fn receipt_commit_by_admin_on_tier1() {
    let f = fixture();
    register_tier1(&f, PROOF3, 0x31);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let record = f.client.commit_receipt_digest(
        &f.admin,
        &b32(&f.env, PROOF3),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_C),
    );
    assert_eq!(record.tier, TIER_SILENT_WITNESS);
    assert_eq!(record.committed_by, f.admin);
    assert_eq!(commit_events(&f), 1);
}

#[test]
fn receipt_commit_by_admin_on_tier2_proof() {
    let f = fixture();
    register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let record = f.client.commit_receipt_digest(
        &f.admin,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(record.committed_by, f.admin);
    assert_eq!(commit_events(&f), 1);
}

#[test]
fn receipt_commitment_absent_before_commit() {
    let f = fixture();
    register_tier2(&f, PROOF1, 0x01);
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF1))
        .is_none());
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[test]
fn receipt_commit_retry_is_idempotent_without_second_event() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let first = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(commit_events(&f), 1);

    // An identical retry returns the stored record and emits nothing.
    let second = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(commit_events(&f), 0);
    assert_eq!(first.committed_at, second.committed_at);
    assert_eq!(first.receipt_digest, second.receipt_digest);
}

#[test]
#[should_panic(expected = "Error(Contract, #70)")]
fn receipt_commit_different_digest_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &BytesN::from_array(&f.env, &DIGEST2),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_D2),
    );
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #68)")]
fn receipt_commit_unknown_proof_rejected() {
    let f = fixture();
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &f.admin,
        &b32(&f.env, 0xFF),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #69)")]
fn receipt_commit_revoked_proof_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.revoke_proof(&f.admin, &b32(&f.env, PROOF1));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #69)")]
fn receipt_commit_expired_proof_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.expire_proof(&f.admin, &b32(&f.env, PROOF1), &1u32);
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #71)")]
fn receipt_commit_zero_digest_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &b32(&f.env, 0x00),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #72)")]
fn receipt_commit_unknown_signer_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    // No signer registered.
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #73)")]
fn receipt_commit_revoked_signer_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.revoke_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn receipt_commit_tier1_requires_admin() {
    let f = fixture();
    register_tier1(&f, PROOF3, 0x31);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    let stranger = Address::generate(&f.env);
    f.client.commit_receipt_digest(
        &stranger,
        &b32(&f.env, PROOF3),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_C),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn receipt_commit_tier2_rejects_non_source() {
    let f = fixture();
    register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    let stranger = Address::generate(&f.env);
    f.client.commit_receipt_digest(
        &stranger,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn receipt_commit_tier3_rejects_non_issuer() {
    let f = fixture();
    register_tier3(&f, PROOF2, 0x11);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    let stranger = Address::generate(&f.env);
    f.client.commit_receipt_digest(
        &stranger,
        &b32(&f.env, PROOF2),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_B),
    );
}

// ---------------------------------------------------------------------------
// Attestation signature binding (host crypto boundary)
// ---------------------------------------------------------------------------

/// A failed attestation traps at the host crypto boundary, writes nothing,
/// and leaves the proof committable by a later valid signature.
#[test]
fn receipt_commit_rejects_tampered_signature() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));

    let result = f.client.try_commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_BAD),
    );
    let shape = match &result {
        Ok(_) => "ok".to_string(),
        Err(Ok(e)) => format!("{:?}", e),
        Err(Err(_)) => "host-invoke".to_string(),
    };
    // The trap is not a contract error: through `try_` the host surfaces it
    // as a Context error (a direct call panics with `Error(Crypto,
    // InvalidInput)` at the `secp256r1_verify` boundary).
    assert_eq!(
        shape, "Error(Context, InvalidAction)",
        "bad signature must trap at the host boundary"
    );
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF1))
        .is_none());

    // The failed attempt did not consume the one-commitment slot.
    let record = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(record.committed_at, COMMITTED_AT);
}

#[test]
fn receipt_commit_rejects_signature_for_other_proof() {
    let f = fixture();
    // SIG_A binds proof [0x11; 32]; committing it for proof [0x22; 32] must fail.
    let source = register_tier2(&f, PROOF2, 0x11);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    let result = f.client.try_commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF2),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert!(result.is_err());
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF2))
        .is_none());
}

#[test]
fn receipt_commit_rejects_signature_for_other_contract() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    // SIG_C2 was signed over this registry's sibling contract address.
    let result = f.client.try_commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_C2),
    );
    assert!(result.is_err());
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF1))
        .is_none());
}

#[test]
fn receipt_commit_rejects_signature_for_other_digest() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    // SIG_D2 attests DIGEST2, not DIGEST1.
    let result = f.client.try_commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_D2),
    );
    assert!(result.is_err());
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF1))
        .is_none());
}

#[test]
fn receipt_commit_rejects_signature_from_other_key() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client
        .add_receipt_signer(&f.admin, &BytesN::from_array(&f.env, &PUB2));
    // SIG_A was produced by PUB1's private key.
    let result = f.client.try_commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &BytesN::from_array(&f.env, &PUB2),
        &sig_a(&f.env),
    );
    assert!(result.is_err());
    assert!(f
        .client
        .get_receipt_commitment(&b32(&f.env, PROOF1))
        .is_none());
}

// ---------------------------------------------------------------------------
// Receipt signer allowlist
// ---------------------------------------------------------------------------

#[test]
fn receipt_signer_add_revoke_lifecycle() {
    let f = fixture();
    assert!(f.client.get_receipt_signer(&pk1(&f.env)).is_none());

    let added = f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    assert!(added.active);
    assert_eq!(added.added_at, COMMITTED_AT);
    assert_eq!(added.revoked_at, 0);
    assert_eq!(add_events(&f), 1);

    // Re-adding an active key is a no-op without a second event.
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    assert_eq!(add_events(&f), 0);

    let revoked = f.client.revoke_receipt_signer(&f.admin, &pk1(&f.env));
    assert!(!revoked.active);
    assert_eq!(revoked.revoked_at, COMMITTED_AT);
    assert_eq!(revoke_events(&f), 1);

    // Revoking twice emits nothing.
    f.client.revoke_receipt_signer(&f.admin, &pk1(&f.env));
    assert_eq!(revoke_events(&f), 0);

    // Re-adding a revoked key reactivates it and emits an add event.
    let reactivated = f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    assert!(reactivated.active);
    assert_eq!(add_events(&f), 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn receipt_signer_add_requires_admin() {
    let f = fixture();
    let stranger = Address::generate(&f.env);
    f.client.add_receipt_signer(&stranger, &pk1(&f.env));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn receipt_signer_revoke_requires_admin() {
    let f = fixture();
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    let stranger = Address::generate(&f.env);
    f.client.revoke_receipt_signer(&stranger, &pk1(&f.env));
}

#[test]
#[should_panic(expected = "Error(Contract, #72)")]
fn receipt_signer_revoke_unknown_rejected() {
    let f = fixture();
    f.client.revoke_receipt_signer(&f.admin, &pk1(&f.env));
}

#[test]
#[should_panic(expected = "Error(Contract, #74)")]
fn receipt_signer_saturation_rejects_ninth() {
    let f = fixture();
    for i in 0..MAX_RECEIPT_SIGNERS {
        let key = BytesN::from_array(&f.env, &[0xA0 + i as u8; 65]);
        f.client.add_receipt_signer(&f.admin, &key);
    }
    let ninth = BytesN::from_array(&f.env, &[0xA8; 65]);
    f.client.add_receipt_signer(&f.admin, &ninth);
}

#[test]
fn receipt_signer_revocation_frees_slot() {
    let f = fixture();
    for i in 0..MAX_RECEIPT_SIGNERS {
        let key = BytesN::from_array(&f.env, &[0xA0 + i as u8; 65]);
        f.client.add_receipt_signer(&f.admin, &key);
    }
    let first = BytesN::from_array(&f.env, &[0xA0; 65]);
    f.client.revoke_receipt_signer(&f.admin, &first);
    assert!(!f.client.get_receipt_signer(&first).unwrap().active);

    let ninth = BytesN::from_array(&f.env, &[0xA8; 65]);
    f.client.add_receipt_signer(&f.admin, &ninth);
    assert!(f.client.get_receipt_signer(&ninth).unwrap().active);
}

// ---------------------------------------------------------------------------
// Durability and pause
// ---------------------------------------------------------------------------

/// Commitments are historical anchors: a later retry still succeeds after the
/// proof is revoked (idempotency is checked before proof status).
#[test]
fn receipt_commitment_survives_proof_revocation() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    f.client.revoke_proof(&f.admin, &b32(&f.env, PROOF1));

    let stored = f.client.get_receipt_commitment(&b32(&f.env, PROOF1));
    assert!(stored.is_some());

    let retry = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(retry.committed_at, COMMITTED_AT);
    assert_eq!(commit_events(&f), 0);
}

/// A *new* digest on a revoked proof is rejected: the occupied commitment
/// slot is reported first (`ReceiptAlreadyCommitted`), while retries of the
/// stored digest keep succeeding.
#[test]
#[should_panic(expected = "Error(Contract, #70)")]
fn receipt_commit_new_digest_after_revocation_rejected() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    f.client.revoke_proof(&f.admin, &b32(&f.env, PROOF1));
    f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &BytesN::from_array(&f.env, &DIGEST2),
        &pk1(&f.env),
        &BytesN::from_array(&f.env, &SIG_D2),
    );
}

/// Registration pauses do not gate receipt commits or signer management;
/// registration itself stays gated.
#[test]
#[should_panic(expected = "Error(Contract, #21)")]
fn receipt_pause_does_not_gate_commits_or_signers() {
    let f = fixture();
    let source = register_tier2(&f, PROOF1, 0x01);

    f.client
        .pause(&f.admin, &PAUSE_DOMAIN_ALL_REGISTRATION, &10_000u64);

    // Signer management is not gated by the registration pause.
    f.client.add_receipt_signer(&f.admin, &pk1(&f.env));
    assert_eq!(add_events(&f), 1);

    // Receipt commits are not gated either.
    let record = f.client.commit_receipt_digest(
        &source,
        &b32(&f.env, PROOF1),
        &digest1(&f.env),
        &pk1(&f.env),
        &sig_a(&f.env),
    );
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(commit_events(&f), 1);

    // Registration remains gated while paused.
    f.client.register_source(
        &source,
        &b32(&f.env, 0x55),
        &b32(&f.env, 0x56),
        &b32(&f.env, 0x57),
    );
}
