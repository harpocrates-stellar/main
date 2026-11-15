//! Tests for tier-bound proof pagination cursors (#1198).

#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, InvokeError};

fn b32(env: &Env, tag: u8, idx: u8) -> BytesN<32> {
    let mut raw = [0u8; 32];
    raw[0] = tag;
    raw[31] = idx;
    BytesN::from_array(env, &raw)
}

fn assert_registry_error<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
    expected: RegistryError,
) {
    assert_eq!(
        res.err(),
        Some(Ok(soroban_sdk::Error::from_contract_error(expected as u32)))
    );
}

#[test]
fn list_proofs_by_tier_returns_deterministic_isolated_pages_per_identity_tier() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    let root = b32(&env, 0xAA, 1);

    client.init(&admin);
    client.add_credential_root(&admin, &root, &b32(&env, 0xAB, 1));
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAC, 1));

    // Interleave registrations across Tier 1 (4 proofs), Tier 2 (5 proofs), Tier 3 (3 proofs).
    let proof_bytes = Bytes::from_slice(&env, &[0x01; 64]);
    for i in 1u8..=4 {
        client.register_anonymous(
            &b32(&env, 0x10, i),
            &b32(&env, 0x11, i),
            &b32(&env, 0x12, i),
            &b32(&env, 0x13, i),
            &root,
            &proof_bytes,
        );
    }
    for i in 1u8..=5 {
        client.register_source(
            &source,
            &b32(&env, 0x20, i),
            &b32(&env, 0x21, i),
            &b32(&env, 0x22, i),
        );
    }
    for i in 1u8..=3 {
        client.register_seal(
            &issuer,
            &b32(&env, 0x30, i),
            &b32(&env, 0x31, i),
            &b32(&env, 0x32, i),
        );
    }

    assert_eq!(client.get_tier_proof_count(&TIER_SILENT_WITNESS), 4);
    assert_eq!(client.get_tier_proof_count(&TIER_CONSISTENT_SOURCE), 5);
    assert_eq!(client.get_tier_proof_count(&TIER_PUBLIC_SEAL), 3);

    // Paginate Tier 2 in pages of 2 -> 2 -> 1.
    let page1 = client.list_proofs_by_tier(&TIER_CONSISTENT_SOURCE, &None, &2);
    assert_eq!(page1.tier, TIER_CONSISTENT_SOURCE);
    assert_eq!(page1.total, 5);
    assert_eq!(page1.proof_ids.len(), 2);
    assert_eq!(page1.proof_ids.get(0).unwrap(), b32(&env, 0x22, 1));
    assert_eq!(page1.proof_ids.get(1).unwrap(), b32(&env, 0x22, 2));
    assert!(page1.has_more);
    assert_eq!(
        page1.next_cursor(),
        Some(TierProofCursor {
            tier: TIER_CONSISTENT_SOURCE,
            next_seq: 3,
        })
    );

    let page2 = client.list_proofs_by_tier(&TIER_CONSISTENT_SOURCE, &page1.next_cursor(), &2);
    assert_eq!(page2.proof_ids.len(), 2);
    assert_eq!(page2.proof_ids.get(0).unwrap(), b32(&env, 0x22, 3));
    assert_eq!(page2.proof_ids.get(1).unwrap(), b32(&env, 0x22, 4));
    assert!(page2.has_more);
    assert_eq!(
        page2.next_cursor(),
        Some(TierProofCursor {
            tier: TIER_CONSISTENT_SOURCE,
            next_seq: 5,
        })
    );

    let page3 = client.list_proofs_by_tier(&TIER_CONSISTENT_SOURCE, &page2.next_cursor(), &2);
    assert_eq!(page3.proof_ids.len(), 1);
    assert_eq!(page3.proof_ids.get(0).unwrap(), b32(&env, 0x22, 5));
    assert!(!page3.has_more);
    assert_eq!(page3.next_cursor(), None);
}

#[test]
fn cross_tier_cursor_reuse_and_forged_cursors_are_rejected_with_invalid_cursor() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let issuer = Address::generate(&env);
    let root = b32(&env, 0xBA, 1);

    client.init(&admin);
    client.add_credential_root(&admin, &root, &b32(&env, 0xBB, 1));
    client.add_issuer(&admin, &issuer, &b32(&env, 0xBC, 1));

    let proof_bytes = Bytes::from_slice(&env, &[0x02; 64]);
    for i in 1u8..=3 {
        client.register_anonymous(
            &b32(&env, 0x40, i),
            &b32(&env, 0x41, i),
            &b32(&env, 0x42, i),
            &b32(&env, 0x43, i),
            &root,
            &proof_bytes,
        );
        client.register_source(
            &source,
            &b32(&env, 0x50, i),
            &b32(&env, 0x51, i),
            &b32(&env, 0x52, i),
        );
        client.register_seal(
            &issuer,
            &b32(&env, 0x60, i),
            &b32(&env, 0x61, i),
            &b32(&env, 0x62, i),
        );
    }

    let tier1_page = client.list_proofs_by_tier(&TIER_SILENT_WITNESS, &None, &1);
    let tier1_cursor = tier1_page.next_cursor();
    assert!(tier1_cursor.is_some());

    // Reusing a Tier 1 cursor on Tier 2 or Tier 3 must fail closed with `InvalidCursor` (#90).
    assert_registry_error(
        client.try_list_proofs_by_tier(&TIER_CONSISTENT_SOURCE, &tier1_cursor, &1),
        RegistryError::InvalidCursor,
    );
    assert_registry_error(
        client.try_list_proofs_by_tier(&TIER_PUBLIC_SEAL, &tier1_cursor, &1),
        RegistryError::InvalidCursor,
    );

    // Forged cursor with unknown tier tag (`99`), zero `next_seq`, or `next_seq > total + 1`.
    assert_registry_error(
        client.try_list_proofs_by_tier(
            &TIER_SILENT_WITNESS,
            &Some(TierProofCursor {
                tier: 99,
                next_seq: 1,
            }),
            &1,
        ),
        RegistryError::InvalidCursor,
    );
    assert_registry_error(
        client.try_list_proofs_by_tier(
            &TIER_SILENT_WITNESS,
            &Some(TierProofCursor {
                tier: TIER_SILENT_WITNESS,
                next_seq: 0,
            }),
            &1,
        ),
        RegistryError::InvalidCursor,
    );
    assert_registry_error(
        client.try_list_proofs_by_tier(
            &TIER_SILENT_WITNESS,
            &Some(TierProofCursor {
                tier: TIER_SILENT_WITNESS,
                next_seq: 5, // total is 3, so max valid sentinel is 4
            }),
            &1,
        ),
        RegistryError::InvalidCursor,
    );

    // Exact sentinel `next_seq == total + 1` returns an empty terminal page cleanly.
    let exhausted = client.list_proofs_by_tier(
        &TIER_SILENT_WITNESS,
        &Some(TierProofCursor {
            tier: TIER_SILENT_WITNESS,
            next_seq: 4,
        }),
        &10,
    );
    assert!(exhausted.proof_ids.is_empty());
    assert!(!exhausted.has_more);
    assert_eq!(exhausted.next_cursor(), None);
    assert_eq!(exhausted.total, 3);
}

#[test]
fn empty_tier_and_invalid_tier_or_limit_boundaries_behave_deterministically() {
    let env = Env::default();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Empty tier returns empty page with `has_more = false` and no continuation cursor.
    let empty = client.list_proofs_by_tier(&TIER_PUBLIC_SEAL, &None, &MAX_TIER_PROOFS_PAGE);
    assert!(empty.proof_ids.is_empty());
    assert!(!empty.has_more);
    assert_eq!(empty.next_cursor(), None);
    assert_eq!(empty.total, 0);
    assert_eq!(empty.tier, TIER_PUBLIC_SEAL);

    // Invalid tier selectors (`0`, `4`) fail closed with `InvalidPublicInputs`.
    assert_registry_error(
        client.try_list_proofs_by_tier(&0, &None, &10),
        RegistryError::InvalidPublicInputs,
    );
    assert_registry_error(
        client.try_list_proofs_by_tier(&4, &None, &10),
        RegistryError::InvalidPublicInputs,
    );
    assert_registry_error(
        client.try_get_tier_proof_count(&0),
        RegistryError::InvalidPublicInputs,
    );

    // `limit == 0` or `limit > MAX_TIER_PROOFS_PAGE` fails closed with `ListLimitExceeded`.
    assert_registry_error(
        client.try_list_proofs_by_tier(&TIER_SILENT_WITNESS, &None, &0),
        RegistryError::ListLimitExceeded,
    );
    assert_registry_error(
        client.try_list_proofs_by_tier(&TIER_SILENT_WITNESS, &None, &(MAX_TIER_PROOFS_PAGE + 1)),
        RegistryError::ListLimitExceeded,
    );
}
