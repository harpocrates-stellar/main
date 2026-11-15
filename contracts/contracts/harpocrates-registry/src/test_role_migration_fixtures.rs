//! Role migration compatibility fixture set and replay harness (#1191).
//!
//! Parses the canonical synthetic fixture corpus in
//! `contracts/fixtures/role_migration_compat_v1.tsv`, replays approved role
//! transitions across simulated contract upgrades (`register_at` code
//! replacement, `upgrade_storage`, `CouncilAction::UpgradeStorage`, and
//! `ProposalAction::UpgradeWasm`), and verifies that every actor retains ONLY
//! its intended write-side and read-side capabilities.
//!
//! No real media, credentials, witness values, or private keys are used.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec as StdVec;

const FIXTURE_TSV: &str = include_str!("../../../fixtures/role_migration_compat_v1.tsv");

const STUB_UPGRADE_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7e, 0x03,
    0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x63, 0x61, 0x6c, 0x6c, 0x00, 0x00, 0x0a, 0x08, 0x01,
    0x06, 0x00, 0x42, 0x8e, 0xdc, 0x2d, 0x0b, 0x00, 0x1e, 0x11, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61,
    0x63, 0x74, 0x65, 0x6e, 0x76, 0x6d, 0x65, 0x74, 0x61, 0x76, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapabilityExpectation {
    can_admin: bool,
    can_issue_seal: bool,
    is_verifiable_issuer: bool,
    can_guardian_pause: bool,
    can_delegate_seal: bool,
    can_delegate_source: bool,
    can_approve_seal: bool,
    can_accept_admin: bool,
    can_propose_council: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureRow {
    scenario: String,
    phase: String,
    actor: String,
    expected: CapabilityExpectation,
}

fn parse_bool_flag(raw: &str) -> Result<bool, String> {
    match raw {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(std::format!("invalid capability flag: {other}")),
    }
}

fn parse_fixture_corpus(src: &str) -> Result<StdVec<FixtureRow>, String> {
    let mut version_seen: Option<u32> = None;
    let mut rows = StdVec::new();

    for (line_idx, raw_line) in src.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: StdVec<&str> = line.split('\t').collect();
        if cols.len() == 2 && cols[0] == "version" {
            let v: u32 = cols[1]
                .parse()
                .map_err(|_| std::format!("line {}: invalid version", line_idx + 1))?;
            if v != 1 {
                return Err(std::format!("unsupported fixture version: {v}"));
            }
            version_seen = Some(v);
            continue;
        }
        if cols.len() != 12 {
            return Err(std::format!(
                "line {}: expected 12 columns, got {}",
                line_idx + 1,
                cols.len()
            ));
        }
        rows.push(FixtureRow {
            scenario: cols[0].to_string(),
            phase: cols[1].to_string(),
            actor: cols[2].to_string(),
            expected: CapabilityExpectation {
                can_admin: parse_bool_flag(cols[3])?,
                can_issue_seal: parse_bool_flag(cols[4])?,
                is_verifiable_issuer: parse_bool_flag(cols[5])?,
                can_guardian_pause: parse_bool_flag(cols[6])?,
                can_delegate_seal: parse_bool_flag(cols[7])?,
                can_delegate_source: parse_bool_flag(cols[8])?,
                can_approve_seal: parse_bool_flag(cols[9])?,
                can_accept_admin: parse_bool_flag(cols[10])?,
                can_propose_council: parse_bool_flag(cols[11])?,
            },
        });
    }

    if version_seen != Some(1) {
        return Err("missing `version\t1` header".to_string());
    }
    if rows.is_empty() {
        return Err("fixture corpus must contain at least one row".to_string());
    }
    Ok(rows)
}

fn slot_b32(env: &Env, tag: u8, seq: u32) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = tag;
    arr[28..32].copy_from_slice(&seq.to_be_bytes());
    BytesN::from_array(env, &arr)
}

/// Simulate redeploying the upgraded contract bytecode at the existing
/// `contract_id` while preserving all persistent storage in-place.
fn simulate_contract_redeploy(env: &Env, contract_id: &Address) {
    env.register_at(contract_id, HarpocratesRegistry, ());
}

struct ProbeContext<'a> {
    env: &'a Env,
    client: &'a HarpocratesRegistryClient<'a>,
    admin_for_cleanup: &'a Address,
    delegation_seal_grantor: &'a Address,
    delegation_source_grantor: &'a Address,
    seq: u32,
}

/// Exercise real write-side and read-side entry points for `actor` and assert
/// that every capability matches `expected` (retaining intended capabilities and
/// rejecting all unintended capabilities).
fn assert_actor_capabilities(
    ctx: &mut ProbeContext<'_>,
    scenario: &str,
    phase: &str,
    actor_name: &str,
    actor: &Address,
    expected: CapabilityExpectation,
) {
    ctx.seq += 1;
    let s = ctx.seq;

    // 1. Admin capability: `is_admin` + `add_credential_root` write probe.
    assert_eq!(
        ctx.client.is_admin(actor),
        expected.can_admin,
        "{scenario}/{phase}/{actor_name}: is_admin mismatch"
    );
    let root = slot_b32(ctx.env, 0xA1, s);
    let admin_res = ctx
        .client
        .try_add_credential_root(actor, &root, &slot_b32(ctx.env, 0xA2, s));
    assert_eq!(
        admin_res.is_ok(),
        expected.can_admin,
        "{scenario}/{phase}/{actor_name}: add_credential_root capability mismatch: {admin_res:?}"
    );

    // 2. Active Tier-3 seal issuance capability: `is_issuer` + `register_seal`.
    assert_eq!(
        ctx.client.is_issuer(actor),
        expected.can_issue_seal,
        "{scenario}/{phase}/{actor_name}: is_issuer mismatch"
    );
    let seal_res = ctx.client.try_register_seal(
        actor,
        &slot_b32(ctx.env, 0xB1, s),
        &slot_b32(ctx.env, 0xB2, s),
        &slot_b32(ctx.env, 0xB3, s),
    );
    assert_eq!(
        seal_res.is_ok(),
        expected.can_issue_seal,
        "{scenario}/{phase}/{actor_name}: register_seal capability mismatch: {seal_res:?}"
    );

    // 3. Verifiable issuer standing (active or within rotation grace window).
    assert_eq!(
        ctx.client.is_issuer_verifiable(actor),
        expected.is_verifiable_issuer,
        "{scenario}/{phase}/{actor_name}: is_issuer_verifiable mismatch"
    );

    // 4. Emergency pause capability (`pause` + immediate `unpause` cleanup).
    let pause_res = ctx
        .client
        .try_pause(actor, &PAUSE_DOMAIN_TIER1_REGISTRATION, &60);
    assert_eq!(
        pause_res.is_ok(),
        expected.can_guardian_pause,
        "{scenario}/{phase}/{actor_name}: pause capability mismatch: {pause_res:?}"
    );
    if pause_res.is_ok() {
        ctx.client
            .unpause(ctx.admin_for_cleanup, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    }

    // 5. Delegated Tier-3 seal capability on `delegation_seal_grantor`'s behalf.
    let del_seal_res = ctx.client.try_register_seal_delegated(
        actor,
        ctx.delegation_seal_grantor,
        &slot_b32(ctx.env, 0xC1, s),
        &slot_b32(ctx.env, 0xC2, s),
        &slot_b32(ctx.env, 0xC3, s),
    );
    assert_eq!(
        del_seal_res.is_ok(),
        expected.can_delegate_seal,
        "{scenario}/{phase}/{actor_name}: register_seal_delegated mismatch: {del_seal_res:?}"
    );

    // 6. Delegated Tier-2 source capability on `delegation_source_grantor`'s behalf.
    let del_src_res = ctx.client.try_register_source_delegated(
        actor,
        ctx.delegation_source_grantor,
        &slot_b32(ctx.env, 0xD1, s),
        &slot_b32(ctx.env, 0xD2, s),
        &slot_b32(ctx.env, 0xD3, s),
    );
    assert_eq!(
        del_src_res.is_ok(),
        expected.can_delegate_source,
        "{scenario}/{phase}/{actor_name}: register_source_delegated mismatch: {del_src_res:?}"
    );

    // 7. Threshold seal approval capability under active `SealPolicy`.
    let app_seal_res = ctx.client.try_approve_seal(
        actor,
        &slot_b32(ctx.env, 0xE1, s),
        &slot_b32(ctx.env, 0xE2, s),
        &slot_b32(ctx.env, 0xE3, s),
    );
    assert_eq!(
        app_seal_res.is_ok(),
        expected.can_approve_seal,
        "{scenario}/{phase}/{actor_name}: approve_seal mismatch: {app_seal_res:?}"
    );

    // 8. Pending admin acceptance standing (non-destructive check when true so
    // the caller controls when `accept_admin` transitions phases; destructive
    // negative `try_accept_admin` check when false!).
    let pending = ctx.client.get_pending_admin();
    assert_eq!(
        pending.as_ref() == Some(actor),
        expected.can_accept_admin,
        "{scenario}/{phase}/{actor_name}: pending_admin mismatch"
    );
    if !expected.can_accept_admin {
        assert!(
            ctx.client.try_accept_admin(actor).is_err(),
            "{scenario}/{phase}/{actor_name}: unintended accept_admin succeeded"
        );
    }

    // 9. AdminCouncil proposal capability (cleanup via cancel when true).
    let council_target = Address::generate(ctx.env);
    let council_res = ctx.client.try_propose_council_action(
        actor,
        &4,
        &council_target,
        &slot_b32(ctx.env, 0xF1, s),
    );
    assert_eq!(
        council_res.is_ok(),
        expected.can_propose_council,
        "{scenario}/{phase}/{actor_name}: propose_council_action mismatch: {council_res:?}"
    );
    if let Ok(Ok(prop_id)) = council_res {
        ctx.client.cancel_council_proposal(actor, &prop_id);
    }
}

fn verify_phase(
    rows: &[FixtureRow],
    scenario: &str,
    phase: &str,
    actors: &BTreeMap<&str, Address>,
    ctx: &mut ProbeContext<'_>,
) -> usize {
    let mut matched = 0usize;
    for row in rows {
        if row.scenario == scenario && row.phase == phase {
            let addr = actors
                .get(row.actor.as_str())
                .unwrap_or_else(|| panic!("unknown actor {} in {scenario}/{phase}", row.actor));
            assert_actor_capabilities(ctx, scenario, phase, &row.actor, addr, row.expected);
            matched += 1;
        }
    }
    assert!(matched > 0, "no fixture rows matched {scenario}/{phase}");
    matched
}

#[test]
fn replay_full_role_migration_compatibility_fixture_set() {
    let rows = parse_fixture_corpus(FIXTURE_TSV).expect("fixture corpus must parse cleanly");
    let mut verified_rows = 0usize;

    // -----------------------------------------------------------------------
    // Scenario 1: v1_conflict_disjoint_migration
    // -----------------------------------------------------------------------
    {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(100_000);
        let cid = env.register(HarpocratesRegistry, ());
        let client = HarpocratesRegistryClient::new(&env, &cid);

        let admin_a = Address::generate(&env);
        let issuer_active = Address::generate(&env);
        let guardian = Address::generate(&env);
        let outsider = Address::generate(&env);
        let dummy_src = Address::generate(&env);

        client.init(&admin_a);
        client.add_issuer(&admin_a, &issuer_active, &slot_b32(&env, 0x01, 1));
        client.set_guardian(&admin_a, &guardian);

        // Install legacy V1 conflicting active issuer record on `admin_a`.
        env.as_contract(&cid, || {
            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
            env.storage().persistent().set(
                &DataKey::Issuer(admin_a.clone()),
                &IssuerRecord {
                    metadata_hash: slot_b32(&env, 0x02, 1),
                    active: true,
                },
            );
        });

        simulate_contract_redeploy(&env, &cid);
        client.upgrade_storage(&admin_a);

        let mut actors = BTreeMap::new();
        actors.insert("admin_a", admin_a.clone());
        actors.insert("issuer_active", issuer_active.clone());
        actors.insert("guardian", guardian);
        actors.insert("outsider", outsider);

        let mut ctx = ProbeContext {
            env: &env,
            client: &client,
            admin_for_cleanup: &admin_a,
            delegation_seal_grantor: &issuer_active,
            delegation_source_grantor: &dummy_src,
            seq: 0,
        };
        verified_rows += verify_phase(
            &rows,
            "v1_conflict_disjoint_migration",
            "post_upgrade",
            &actors,
            &mut ctx,
        );
    }

    // -----------------------------------------------------------------------
    // Scenario 2: pending_admin_transfer_across_upgrade
    // -----------------------------------------------------------------------
    {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(200_000);
        let cid = env.register(HarpocratesRegistry, ());
        let client = HarpocratesRegistryClient::new(&env, &cid);

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);
        let outsider = Address::generate(&env);
        let dummy = Address::generate(&env);

        client.init(&admin_a);
        client.propose_admin(&admin_a, &admin_b);

        simulate_contract_redeploy(&env, &cid);
        client.upgrade_storage(&admin_a);

        let mut actors = BTreeMap::new();
        actors.insert("admin_a", admin_a.clone());
        actors.insert("admin_b", admin_b.clone());
        actors.insert("outsider", outsider);

        {
            let mut ctx = ProbeContext {
                env: &env,
                client: &client,
                admin_for_cleanup: &admin_a,
                delegation_seal_grantor: &dummy,
                delegation_source_grantor: &dummy,
                seq: 100,
            };
            verified_rows += verify_phase(
                &rows,
                "pending_admin_transfer_across_upgrade",
                "post_upgrade_pre_accept",
                &actors,
                &mut ctx,
            );
        }

        // Complete pending transfer after upgrade, then assign former admin_a as issuer.
        client.accept_admin(&admin_b);
        client.add_issuer(&admin_b, &admin_a, &slot_b32(&env, 0x03, 1));

        {
            let mut ctx = ProbeContext {
                env: &env,
                client: &client,
                admin_for_cleanup: &admin_b,
                delegation_seal_grantor: &admin_a,
                delegation_source_grantor: &dummy,
                seq: 200,
            };
            verified_rows += verify_phase(
                &rows,
                "pending_admin_transfer_across_upgrade",
                "post_upgrade_accepted",
                &actors,
                &mut ctx,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Scenario 3: issuer_rotation_and_delegation_across_upgrade
    // -----------------------------------------------------------------------
    {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(300_000);
        let cid = env.register(HarpocratesRegistry, ());
        let client = HarpocratesRegistryClient::new(&env, &cid);

        let admin_a = Address::generate(&env);
        let issuer_retired = Address::generate(&env);
        let issuer_active = Address::generate(&env);
        let source_grantor = Address::generate(&env);
        let delegate_seal = Address::generate(&env);
        let delegate_source = Address::generate(&env);

        client.init(&admin_a);
        client.add_issuer(&admin_a, &issuer_retired, &slot_b32(&env, 0x04, 1));
        client.add_issuer(&admin_a, &issuer_active, &slot_b32(&env, 0x04, 2));

        client.grant_delegation(
            &issuer_retired,
            &delegate_seal,
            &DELEGATION_SCOPE_REGISTER_SEAL,
            &3_600,
        );
        client.grant_delegation(
            &source_grantor,
            &delegate_source,
            &DELEGATION_SCOPE_REGISTER_SOURCE,
            &3_600,
        );
        let grace_end = client.rotate_issuer(&admin_a, &issuer_retired, &issuer_active, &600);

        simulate_contract_redeploy(&env, &cid);
        client.upgrade_storage(&admin_a);

        let mut actors = BTreeMap::new();
        actors.insert("admin_a", admin_a.clone());
        actors.insert("issuer_retired", issuer_retired.clone());
        actors.insert("issuer_active", issuer_active);
        actors.insert("delegate_seal", delegate_seal);
        actors.insert("delegate_source", delegate_source);

        {
            let mut ctx = ProbeContext {
                env: &env,
                client: &client,
                admin_for_cleanup: &admin_a,
                delegation_seal_grantor: &issuer_retired,
                delegation_source_grantor: &source_grantor,
                seq: 300,
            };
            verified_rows += verify_phase(
                &rows,
                "issuer_rotation_and_delegation_across_upgrade",
                "post_upgrade_in_grace",
                &actors,
                &mut ctx,
            );
        }

        env.ledger().set_timestamp(grace_end);
        client.finalize_issuer_rotation(&issuer_retired);

        {
            let mut ctx = ProbeContext {
                env: &env,
                client: &client,
                admin_for_cleanup: &admin_a,
                delegation_seal_grantor: &issuer_retired,
                delegation_source_grantor: &source_grantor,
                seq: 400,
            };
            verified_rows += verify_phase(
                &rows,
                "issuer_rotation_and_delegation_across_upgrade",
                "post_upgrade_grace_settled",
                &actors,
                &mut ctx,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Scenario 4: threshold_seal_and_revoked_signer_across_upgrade
    // -----------------------------------------------------------------------
    {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(400_000);
        let cid = env.register(HarpocratesRegistry, ());
        let client = HarpocratesRegistryClient::new(&env, &cid);

        let admin_a = Address::generate(&env);
        let issuer_active = Address::generate(&env);
        let issuer_revoked = Address::generate(&env);
        let outsider = Address::generate(&env);

        client.init(&admin_a);
        client.add_issuer(&admin_a, &issuer_active, &slot_b32(&env, 0x05, 1));
        client.add_issuer(&admin_a, &issuer_revoked, &slot_b32(&env, 0x05, 2));

        let ver = client.create_seal_policy(&admin_a, &2, &3, &3_600, &0);
        client.add_seal_policy_signer(&admin_a, &ver, &issuer_active);
        client.add_seal_policy_signer(&admin_a, &ver, &issuer_revoked);

        // Revoked signer casts a partial approval before being revoked.
        let shared_proof = slot_b32(&env, 0x55, 1);
        assert!(!client.approve_seal(
            &issuer_revoked,
            &shared_proof,
            &slot_b32(&env, 0x56, 1),
            &slot_b32(&env, 0x57, 1),
        ));
        client.revoke_issuer(&admin_a, &issuer_revoked);

        simulate_contract_redeploy(&env, &cid);
        client.upgrade_storage(&admin_a);

        // Pre-revocation partial approval must NOT remain valid after upgrade.
        assert_eq!(client.get_seal_approval_count(&shared_proof), 0);

        let mut actors = BTreeMap::new();
        actors.insert("admin_a", admin_a.clone());
        actors.insert("issuer_active", issuer_active.clone());
        actors.insert("issuer_revoked", issuer_revoked);
        actors.insert("outsider", outsider);

        let mut ctx = ProbeContext {
            env: &env,
            client: &client,
            admin_for_cleanup: &admin_a,
            delegation_seal_grantor: &issuer_active,
            delegation_source_grantor: &issuer_active,
            seq: 500,
        };
        verified_rows += verify_phase(
            &rows,
            "threshold_seal_and_revoked_signer_across_upgrade",
            "post_upgrade",
            &actors,
            &mut ctx,
        );
    }

    // -----------------------------------------------------------------------
    // Scenario 5: council_governed_upgrade_boundaries
    // -----------------------------------------------------------------------
    {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(500_000);
        let cid = env.register(HarpocratesRegistry, ());
        let client = HarpocratesRegistryClient::new(&env, &cid);

        let admin_a = Address::generate(&env);
        let issuer_active = Address::generate(&env);
        let council_m1 = Address::generate(&env);
        let council_m2 = Address::generate(&env);
        let outsider = Address::generate(&env);

        client.init(&admin_a);
        client.add_issuer(&admin_a, &issuer_active, &slot_b32(&env, 0x06, 1));

        let mut members = Vec::new(&env);
        members.push_back(council_m1.clone());
        members.push_back(council_m2.clone());
        client.set_admin_council(&admin_a, &members, &2);

        // Simulate legacy V1 conflict before council executes UpgradeStorage.
        env.as_contract(&cid, || {
            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
            env.storage().persistent().set(
                &DataKey::Issuer(admin_a.clone()),
                &IssuerRecord {
                    metadata_hash: slot_b32(&env, 0x06, 2),
                    active: true,
                },
            );
        });

        env.ledger()
            .set_timestamp(500_000 + DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);
        simulate_contract_redeploy(&env, &cid);

        let prop_id =
            client.propose_council_action(&council_m1, &3, &cid, &slot_b32(&env, 0x00, 0));
        client.approve_council_proposal(&council_m1, &prop_id);
        client.approve_council_proposal(&council_m2, &prop_id);
        client.execute_council_proposal(&council_m2, &prop_id);

        // Unilateral admin revoke_issuer remains blocked by active council.
        assert_eq!(
            client.try_revoke_issuer(&admin_a, &issuer_active),
            Err(Ok(soroban_sdk::Error::from_contract_error(
                RegistryError::InsufficientApprovals as u32
            )))
        );

        let mut actors = BTreeMap::new();
        actors.insert("admin_a", admin_a.clone());
        actors.insert("issuer_active", issuer_active.clone());
        actors.insert("council_m1", council_m1);
        actors.insert("council_m2", council_m2);
        actors.insert("outsider", outsider);

        let mut ctx = ProbeContext {
            env: &env,
            client: &client,
            admin_for_cleanup: &admin_a,
            delegation_seal_grantor: &issuer_active,
            delegation_source_grantor: &issuer_active,
            seq: 600,
        };
        verified_rows += verify_phase(
            &rows,
            "council_governed_upgrade_boundaries",
            "post_upgrade",
            &actors,
            &mut ctx,
        );
    }

    assert_eq!(
        verified_rows,
        rows.len(),
        "every row in role_migration_compat_v1.tsv must be replayed and verified"
    );
}

#[test]
fn timelocked_wasm_upgrade_preserves_role_storage_and_fixture_parser_fails_closed() {
    // 1. Parser boundary / malformed fixture rejections.
    assert!(parse_fixture_corpus("# empty\n").is_err());
    assert!(parse_fixture_corpus("version\t2\n").is_err());
    assert!(parse_fixture_corpus("version\t1\nbad\trow\n").is_err());
    assert!(parse_fixture_corpus("version\t1\ns\tp\ta\t2\t0\t0\t0\t0\t0\t0\t0\t0\n").is_err());

    // 2. Real timelocked `UpgradeWasm` execution preserves role & delegation records.
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(600_000);
    let cid = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &cid);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let guardian = Address::generate(&env);
    let delegate = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &slot_b32(&env, 0x71, 1));
    client.set_guardian(&admin, &guardian);
    client.grant_delegation(&issuer, &delegate, &DELEGATION_SCOPE_REGISTER_SEAL, &7_200);

    let new_wasm_hash = env.deployer().upload_contract_wasm(STUB_UPGRADE_WASM);
    let prop_id = client.propose_timelocked_action(
        &admin,
        &(ProposalAction::UpgradeWasm as u32),
        &cid,
        &new_wasm_hash,
    );
    env.ledger()
        .set_timestamp(600_000 + DEFAULT_TIMELOCK_MIN_DELAY_SECS + 1);
    client.execute_timelocked_proposal(&admin, &prop_id);

    env.as_contract(&cid, || {
        assert_eq!(
            env.storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::Admin),
            Some(admin.clone())
        );
        assert_eq!(
            env.storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::Guardian),
            Some(guardian.clone())
        );
        let stored_issuer: IssuerRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()))
            .expect("issuer must survive wasm upgrade");
        assert!(stored_issuer.active);
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::Delegation(issuer.clone(), delegate.clone())));
    });
}
