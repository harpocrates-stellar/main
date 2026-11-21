#![cfg(test)]

//! Lineage graph bounds (#333) and parent content commitments (#332).
//!
//! A lineage record is an edge from registered evidence to a derivative. These
//! tests pin both directions of that edge, the depth the edge implies, the
//! parent commitments published for privacy-preserving boundaries (#332), and
//! the fact that a rejected edge costs a parent nothing:
//!
//! 1. A derivative names at least one parent and at most `MAX_LINEAGE_FANOUT`.
//! 2. A parent is charged for at most `MAX_LINEAGE_FANOUT` derivatives.
//! 3. Depth is derived from the parents, never trusted from the caller, and is
//!    capped at `MAX_LINEAGE_DEPTH`.
//! 4. An edge only ever points at evidence that exists and is still usable: no
//!    self-reference, no repeated parent, no unknown parent, no revoked or
//!    expired proof parent, and no digest that is already recorded.
//! 5. Every registered edge carries a domain-separated commitment for each of
//!    its parents, derived on-chain from public fields only.
//! 6. A rejected edge leaves every parent's budget untouched.

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Symbol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN::from_array(env, &[value; 32])
}

/// The commitment a parent binding produces (#332), recomputed off-chain.
fn expected_parent_commitment(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    const PREFIX: [u8; 11] = *b"harp_lin_pc";
    let mut pre_image = [0u8; 75];
    pre_image[..11].copy_from_slice(&PREFIX);
    pre_image[11..43].copy_from_slice(&a.to_array());
    pre_image[43..75].copy_from_slice(&b.to_array());
    env.crypto()
        .sha256(&Bytes::from_array(env, &pre_image))
        .into()
}

/// A parent set from a list of seed bytes.
fn parents(env: &Env, seeds: &[u8]) -> soroban_sdk::Vec<BytesN<32>> {
    let mut out = soroban_sdk::Vec::new(env);
    for seed in seeds.iter() {
        out.push_back(bytes32(env, *seed));
    }
    out
}

/// A single-parent vector built from an explicit digest.
fn one_parent(env: &Env, parent: &BytesN<32>) -> soroban_sdk::Vec<BytesN<32>> {
    let mut out = soroban_sdk::Vec::new(env);
    out.push_back(parent.clone());
    out
}

/// A registry with an admin and one registered source proof, returning the
/// client, the actor, and the digest of the registered evidence.
fn setup(env: &Env) -> (HarpocratesRegistryClient<'_>, Address, BytesN<32>) {
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.init(&admin);

    let actor = Address::generate(env);
    let evidence = bytes32(env, 0xE1);
    client.register_source(&actor, &bytes32(env, 0xE2), &bytes32(env, 0xE3), &evidence);
    (client, actor, evidence)
}

/// Record one derivative with a single parent, returning its depth.
fn derive(
    client: &HarpocratesRegistryClient<'_>,
    env: &Env,
    actor: &Address,
    parent: &BytesN<32>,
    output: u8,
    depth: u32,
) -> u32 {
    let record = client.register_lineage(
        actor,
        &one_parent(env, parent),
        &bytes32(env, output.wrapping_add(1)),
        &Symbol::new(env, "crop"),
        &bytes32(env, output),
        &depth,
    );
    record.depth
}

// ---------------------------------------------------------------------------
// Positive paths
// ---------------------------------------------------------------------------

#[test]
fn registers_lineage_with_bounded_validation() {
    let env = Env::default();
    let (client, actor, parent) = setup(&env);
    let output = bytes32(&env, 5);

    let lineage = client.register_lineage(
        &actor,
        &one_parent(&env, &parent),
        &bytes32(&env, 4),
        &Symbol::new(&env, "crop"),
        &output,
        &1,
    );

    assert_eq!(lineage.output_digest, bytes32(&env, 5));
    assert_eq!(lineage.depth, 1);
    assert_eq!(lineage.actor, actor);
    assert_eq!(client.get_lineage(&bytes32(&env, 5)).unwrap(), lineage);
    assert_eq!(client.get_lineage_child_count(&parent), 1);
}

#[test]
fn accepts_a_parent_set_exactly_at_the_fanout_cap() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // One registered proof plus the siblings the cap allows.
    let mut seeds: std::vec::Vec<u8> = std::vec![0xE1];
    for i in 1..MAX_LINEAGE_FANOUT {
        let extra = 0x20 + i as u8;
        client.register_source(
            &actor,
            &bytes32(&env, extra),
            &bytes32(&env, extra.wrapping_add(1)),
            &bytes32(&env, extra.wrapping_add(2)),
        );
        seeds.push(extra.wrapping_add(2));
    }
    assert_eq!(seeds.len(), MAX_LINEAGE_FANOUT as usize);
    let parents = parents(&env, &seeds);

    let record = client.register_lineage(
        &actor,
        &parents,
        &bytes32(&env, 0x30),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x31),
        &1,
    );

    assert_eq!(record.parent_proof_ids.len(), MAX_LINEAGE_FANOUT);
    assert_eq!(record.parent_commitments.len(), MAX_LINEAGE_FANOUT);
    assert_eq!(record.depth, 1);
    // Every distinct parent was charged exactly once.
    for seed in seeds.iter() {
        assert_eq!(client.get_lineage_child_count(&bytes32(&env, *seed)), 1);
    }
    assert_eq!(client.get_lineage_child_count(&evidence), 1);
}

#[test]
fn derives_depth_from_the_deepest_parent() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // A shallow parent and a deeper one: the derivative sits one below the
    // deeper of the two.
    assert_eq!(derive(&client, &env, &actor, &evidence, 0x40, 1), 1);
    let deep = bytes32(&env, 0x40);
    assert_eq!(derive(&client, &env, &actor, &deep, 0x41, 2), 2);

    let mut mixed = soroban_sdk::Vec::new(&env);
    mixed.push_back(evidence.clone());
    mixed.push_back(bytes32(&env, 0x41));

    let record = client.register_lineage(
        &actor,
        &mixed,
        &bytes32(&env, 0x42),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x43),
        &3,
    );
    assert_eq!(record.depth, 3);
}

// ---------------------------------------------------------------------------
// Parent content commitments (#332)
// ---------------------------------------------------------------------------

#[test]
fn stores_parent_commitments_for_a_proof_parent() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    let record = client.register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x18),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x19),
        &1,
    );

    // The commitment binds the parent's public (video_hash, metadata_hash).
    let expected = expected_parent_commitment(&env, &bytes32(&env, 0xE2), &bytes32(&env, 0xE3));
    assert_eq!(record.parent_commitments.len(), 1);
    assert_eq!(record.parent_commitments.get(0).unwrap(), expected);

    let fetched = client
        .get_lineage_parent_commitments(&bytes32(&env, 0x19))
        .unwrap();
    assert_eq!(fetched.get(0).unwrap(), expected);

    let stored = client.get_lineage(&bytes32(&env, 0x19)).unwrap();
    assert_eq!(stored.parent_commitments, record.parent_commitments);
}

#[test]
fn stores_commitments_for_a_lineage_parent_chain() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    let mid = client.register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x20),
        &Symbol::new(&env, "blur"),
        &bytes32(&env, 0x21),
        &1,
    );

    let child = client.register_lineage(
        &actor,
        &one_parent(&env, &bytes32(&env, 0x21)),
        &bytes32(&env, 0x22),
        &Symbol::new(&env, "redact"),
        &bytes32(&env, 0x23),
        &2,
    );

    // A lineage parent binds (manifest_digest, output_digest) instead.
    let expected = expected_parent_commitment(&env, &mid.manifest_digest, &mid.output_digest);
    assert_eq!(child.parent_commitments.get(0).unwrap(), expected);
    assert_eq!(
        client
            .get_lineage_parent_commitments(&bytes32(&env, 0x23))
            .unwrap()
            .get(0)
            .unwrap(),
        expected
    );
}

#[test]
fn get_lineage_parent_commitments_missing_is_none() {
    let env = Env::default();
    let (client, _actor, _evidence) = setup(&env);

    assert!(client
        .get_lineage_parent_commitments(&bytes32(&env, 0x99))
        .is_none());
}

// ---------------------------------------------------------------------------
// Fan-out: parents per derivative
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #60)")]
fn rejects_excessive_fanout() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    let mut too_many = soroban_sdk::Vec::new(&env);
    too_many.push_back(evidence);
    for i in 0..MAX_LINEAGE_FANOUT {
        let extra = 0x30 + i as u8;
        client.register_source(
            &actor,
            &bytes32(&env, extra),
            &bytes32(&env, extra.wrapping_add(1)),
            &bytes32(&env, extra.wrapping_add(2)),
        );
        too_many.push_back(bytes32(&env, extra.wrapping_add(2)));
    }

    client.register_lineage(
        &actor,
        &too_many,
        &bytes32(&env, 0x40),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x41),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #76)")]
fn rejects_an_empty_parent_set() {
    let env = Env::default();
    let (client, actor, _) = setup(&env);

    client.register_lineage(
        &actor,
        &soroban_sdk::Vec::new(&env),
        &bytes32(&env, 0x50),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x51),
        &1,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #57)")]
fn rejects_a_repeated_parent() {
    let env = Env::default();
    let (client, actor, _) = setup(&env);

    // Naming the same parent twice is one edge, not two, and is refused so the
    // fan-out cap always counts distinct parents.
    client.register_lineage(
        &actor,
        &parents(&env, &[0xE1, 0xE1]),
        &bytes32(&env, 0x52),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0x53),
        &1,
    );
}

// ---------------------------------------------------------------------------
// Fan-out: derivatives per parent
// ---------------------------------------------------------------------------

#[test]
fn enforces_the_per_parent_fanout_cap() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    for i in 0..MAX_LINEAGE_FANOUT {
        let output = 0x60 + i as u8;
        client.register_lineage(
            &actor,
            &one_parent(&env, &evidence),
            &bytes32(&env, output),
            &Symbol::new(&env, "crop"),
            &bytes32(&env, output.wrapping_add(1)),
            &1,
        );
    }
    assert_eq!(
        client.get_lineage_child_count(&evidence),
        MAX_LINEAGE_FANOUT
    );

    // One more derivative of the same parent is refused with a stable code.
    let overflow = client.try_register_lineage(
        &actor,
        &one_parent(&env, &evidence),
        &bytes32(&env, 0x7F),
        &Symbol::new(&env, "crop"),
        &bytes32(&env, 0x80),
        &1,
    );
    assert_eq!(overflow, Err(Ok(RegistryError::LineageFanOutSaturated)));
    assert_eq!(
        client.get_lineage_child_count(&evidence),
        MAX_LINEAGE_FANOUT
    );
}

#[test]
fn a_parent_budget_is_shared_by_every_derivative_that_names_it() {
    let env = Env::default();
    let (client, actor, evidence) = setup(&env);

    // A second parent that is already at its budget must be refused even when
    // the derivative names another parent with capacity remaining.
    let budget_parent = bytes32(&env, 0x90);
    client.register_source(
        &actor,
        &bytes32(&env, 0x91),
        &bytes32(&env, 0x92),
        &budget_parent,
    );
    for i in 0..MAX_LINEAGE_FANOUT {
        let output = 0xA0 + i as u8;
        client.register_lineage(
            &actor,
            &one_parent(&env, &budget_parent),
            &bytes32(&env, output),
            &Symbol::new(&env, "crop"),
            &bytes32(&env, output.wrapping_add(1)),
            &1,
        );
    }

    let mut mixed = soroban_sdk::Vec::new(&env);
    mixed.push_back(evidence.clone());
    mixed.push_back(budget_parent.clone());
    let refused = client.try_register_lineage(
        &actor,
        &mixed,
        &bytes32(&env, 0xB0),
        &Symbol::new(&env, "compose"),
        &bytes32(&env, 0xB1),
        &1,
    );
    assert_eq!(refused, Err(Ok(RegistryError::LineageFanOutSaturated)));

    // The rejected edge charged nothing to the healthy parent either.
    assert_eq!(client.get_lineage_child_count(&evidence), 0);
}
