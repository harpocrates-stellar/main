use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};

fn setup() -> (Env, Address, Address, Address, BytesN<32>) {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();
    env.ledger().set_sequence_number(50);
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = BytesN::from_array(&env, &[1; 32]);
    client.init(&admin);
    client.set_proof_ttl(&admin, &100);
    client.register_source(
        &source,
        &BytesN::from_array(&env, &[2; 32]),
        &BytesN::from_array(&env, &[3; 32]),
        &proof_id,
    );
    (env, contract_id, admin, source, proof_id)
}

#[test]
fn revoked_status_details_keep_first_ledger_and_statement_identity() {
    let (env, contract_id, admin, _, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let original = client.get_proof(&proof_id).unwrap();
    let envelope = client.get_metadata_envelope(&proof_id);

    env.ledger().set_sequence_number(100);
    env.ledger().set_timestamp(1_050);
    client.revoke_proof(&admin, &proof_id);
    let expected = ProofStatusDetails {
        status: ProofVerificationStatus::Revoked,
        revoked_effective_ledger: Some(100),
    };
    assert_eq!(client.get_proof_status_details(&proof_id), expected);

    // Advancing both clocks past proof expiry must not replace revocation time.
    env.ledger().set_sequence_number(150);
    env.ledger().set_timestamp(1_200);
    assert_eq!(client.get_proof_status_details(&proof_id), expected);
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(client.get_proof_status_details(&proof_id), expected);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Revoked
    );

    let mut expected_record = original.clone();
    expected_record.status = STATUS_REVOKED;
    assert_eq!(client.get_proof(&proof_id), Some(expected_record.clone()));
    assert_eq!(
        client.get_by_video(&original.video_hash),
        Some(expected_record)
    );
    assert_eq!(client.get_metadata_envelope(&proof_id), envelope);
    // Repeat revocations retain the existing append-only history behavior.
    assert_eq!(client.get_proof_history_count(&proof_id), 3);
    assert_eq!(
        client
            .get_proof_history_at(&proof_id, &2)
            .unwrap()
            .timestamp,
        1_050
    );
    assert_eq!(
        client
            .get_proof_history_at(&proof_id, &3)
            .unwrap()
            .timestamp,
        1_200
    );
}

#[test]
fn status_details_preserve_expiry_boundary_and_not_found() {
    let (env, contract_id, admin, _, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let valid = ProofStatusDetails {
        status: ProofVerificationStatus::Valid,
        revoked_effective_ledger: None,
    };
    assert_eq!(client.get_proof_status_details(&proof_id), valid);
    env.ledger().set_timestamp(1_100);
    assert_eq!(client.get_proof_status_details(&proof_id), valid);
    env.ledger().set_timestamp(1_101);
    let expired = ProofStatusDetails {
        status: ProofVerificationStatus::Expired,
        revoked_effective_ledger: None,
    };
    assert_eq!(client.get_proof_status_details(&proof_id), expired);
    client.expire_proof(&admin, &proof_id, &1);
    assert_eq!(client.get_proof_status_details(&proof_id), expired);
    assert_eq!(
        client.get_proof_status_details(&BytesN::from_array(&env, &[99; 32])),
        ProofStatusDetails {
            status: ProofVerificationStatus::NotFound,
            revoked_effective_ledger: None,
        }
    );
}

#[test]
fn legacy_revocation_ledger_remains_unknown_after_repeat_revocation() {
    let (env, contract_id, admin, _, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    // Seed the pre-feature stored format, which never recorded a ledger.
    env.as_contract(&contract_id, || {
        let mut record = get_proof_record(&env, &proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
    });
    let expected = ProofStatusDetails {
        status: ProofVerificationStatus::Revoked,
        revoked_effective_ledger: None,
    };
    assert_eq!(client.get_proof_status_details(&proof_id), expected);
    env.ledger().set_sequence_number(150);
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(client.get_proof_status_details(&proof_id), expected);
}

#[test]
fn batch_revocation_preserves_existing_effective_ledger() {
    let (env, contract_id, admin, source, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let second = BytesN::from_array(&env, &[4; 32]);
    client.register_source(
        &source,
        &BytesN::from_array(&env, &[5; 32]),
        &BytesN::from_array(&env, &[6; 32]),
        &second,
    );
    env.ledger().set_sequence_number(100);
    client.revoke_proof(&admin, &proof_id);
    env.ledger().set_sequence_number(150);
    client.revoke_proofs(
        &admin,
        &soroban_sdk::vec![&env, proof_id.clone(), second.clone()],
        &42,
    );
    assert_eq!(
        client
            .get_proof_status_details(&proof_id)
            .revoked_effective_ledger,
        Some(100)
    );
    assert_eq!(
        client.get_proof_status_details(&second),
        ProofStatusDetails {
            status: ProofVerificationStatus::Revoked,
            revoked_effective_ledger: Some(150),
        }
    );
}

#[test]
fn rejected_revocations_leave_no_effective_ledger() {
    let (env, contract_id, admin, _, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let stranger = Address::generate(&env);
    env.ledger().set_sequence_number(100);
    assert!(client.try_revoke_proof(&stranger, &proof_id).is_err());
    let unknown = BytesN::from_array(&env, &[99; 32]);
    assert!(client
        .try_revoke_proofs(
            &admin,
            &soroban_sdk::vec![&env, proof_id.clone(), unknown],
            &1
        )
        .is_err());
    assert_eq!(
        client.get_proof_status_details(&proof_id),
        ProofStatusDetails {
            status: ProofVerificationStatus::Valid,
            revoked_effective_ledger: None,
        }
    );
    assert_eq!(client.get_proof_history_count(&proof_id), 1);
    env.as_contract(&contract_id, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::ProofRevocationLedger(proof_id.clone())));
    });
    // A rolled-back write must not become the effective ledger of a later success.
    env.ledger().set_sequence_number(150);
    client.revoke_proof(&admin, &proof_id);
    assert_eq!(
        client
            .get_proof_status_details(&proof_id)
            .revoked_effective_ledger,
        Some(150)
    );
}

#[test]
fn effective_ledger_survives_persistent_storage_retention() {
    let (env, contract_id, admin, _, proof_id) = setup();
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    env.ledger().set_sequence_number(100);
    client.revoke_proof(&admin, &proof_id);
    // Maintenance must retain both persistent entries, without changing the
    // recorded revocation ledger. Restoration likewise includes both keys.
    env.as_contract(&contract_id, || {
        for key in [
            DataKey::Proof(proof_id.clone()),
            DataKey::ProofRevocationLedger(proof_id.clone()),
        ] {
            env.storage().persistent().extend_ttl(
                &key,
                BUMP_THRESHOLD_LEDGERS,
                BUMP_TARGET_LEDGERS,
            );
        }
        env.storage()
            .instance()
            .extend_ttl(BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
    });
    env.ledger().set_sequence_number(100_100);
    assert_eq!(
        client.get_proof_status_details(&proof_id),
        ProofStatusDetails {
            status: ProofVerificationStatus::Revoked,
            revoked_effective_ledger: Some(100),
        }
    );
}
