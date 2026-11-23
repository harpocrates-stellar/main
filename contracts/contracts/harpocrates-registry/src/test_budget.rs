//! Soroban resource-budget baseline tests (#94)
//!
//! These tests capture CPU-instruction and memory-byte baselines for every
//! high-cost registry operation and assert they stay within declared
//! thresholds.  The baselines serve as regression guards: any commit that
//! accidentally inflates resource consumption will fail CI.
//!
//! Budget enforcement against Soroban host limits is tested implicitly:
//! the host would reject any operation whose budget exceeded the default
//! network limits; our threshold assertions catch regressions before they
//! reach that point.  (Deliberate host-enforcement tests that set tight
//! `reset_limits` were removed because the Soroban test environment can
//! crash on budget-exhaustion destructors.)
//!
//! ## Threshold design
//!
//! Baselines are set with a generous multiplier (3×) above the measured
//! worst-case inputs to absorb minor SDK/compiler variance while still
//! catching real regressions.  Each test:
//!   1. Resets the budget before the target call.
//!   2. Executes the target call (with worst-case inputs where applicable).
//!   3. Reads `cpu_instruction_cost()` and `memory_bytes_cost()` from
//!      `env.cost_estimate().budget()`.
//!   4. Asserts both are below the declared maximum.
//!
//! **Note:** These baselines may need calibration on first CI run as actual
//! Soroban host overhead varies.  The thresholds include a 3× safety margin.
//!
//! ## Operations under test
//!
//! | Operation                    | Justification                              |
//! |------------------------------|--------------------------------------------|
//! | `init`                       | One-time setup; must be cheap.             |
//! | `add_issuer`                 | Admin action; writes persistent storage.   |
//! | `add_credential_root`        | Admin action; writes persistent storage.   |
//! | `set_verifier`               | Admin action; writes persistent storage.   |
//! | `register_source`            | Most common tier-2 path.                   |
//! | `register_seal`              | Tier-3 path with issuer lookup.            |
//! | `register_anonymous`         | Tier-1 path with nullifier + ZK boundary.  |
//! | `register_anonymous_verified`| Tier-1 path with external verifier call.   |
//! | `revoke_proof`               | Admin action; mutates existing record.     |
//! | `revoke_proofs`              | Admin action; batch mutates up to 20 records. |
//! | `get_proof_status`           | Read-only query; must be sub-linear.       |
//! | `get_statuses_by_video`      | Read-only batch query by video hash.       |
//! | `list_lineage_children`      | Read-only query; full page read bounds.    |
//! | `list_credential_roots`      | Read-only query; paginates credential roots.|
//! | `open_dispute`               | Dispute entry point; baseline and worst-case open cap. |
//! | `respond_dispute`            | Dispute entry point; baseline and worst-case response. |
//! | `supersede_dispute`          | Dispute entry point; baseline and worst-case cycle guard. |
//! | `register_lineage`           | Lineage entry point; baseline and worst-case fanout/depth. |
//!
//! ## Variance policy
//!
//! - These tests run with `mock_all_auths()` so auth cost is excluded.
//! - Budgets are reset immediately before the measured call, so setup
//!   costs (contract registration, earlier admin calls) are excluded.
//! - The chosen baselines represent worst-case inputs (full 32-byte
//!   arrays, maximal metadata, presence of all optional fields).
//! - Repeated-registration tests ensure no unbounded growth across calls.
#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Bytes, Env};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[cfg(test)]
fn proof_buf(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0xAB, 0xCD, 0xEF, 0x01])
}

#[cfg(test)]
fn make_public_inputs(
    env: &Env,
    video_hash: &BytesN<32>,
    credential_root: &BytesN<32>,
    nullifier: &BytesN<32>,
) -> Bytes {
    let mut vh = [0u8; 32];
    video_hash.copy_into_slice(&mut vh);
    let mut cr = [0u8; 32];
    credential_root.copy_into_slice(&mut cr);
    let mut nu = [0u8; 32];
    nullifier.copy_into_slice(&mut nu);

    let mut buf = [0u8; 160];
    buf[16..32].copy_from_slice(&vh[..16]);
    buf[48..64].copy_from_slice(&vh[16..]);
    buf[64..96].copy_from_slice(&cr);
    buf[96..128].copy_from_slice(&nu);
    let mut domain = [0u8; 32];
    expected_domain_tag(env).copy_into_slice(&mut domain);
    buf[128..160].copy_from_slice(&domain);
    Bytes::from_array(env, &buf)
}

// ---------------------------------------------------------------------------
// Mock verifier (same pattern as other test modules)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[contract]
struct MockBudgetVerifier;

#[cfg(test)]
#[contractimpl]
impl MockBudgetVerifier {
    pub fn verify_proof(_env: Env, public_inputs: Bytes, proof: Bytes) {
        let len = public_inputs.len();
        if !(matches!(len, 128 | 160 | 224 | 256)) || proof.is_empty() {
            panic!("invalid proof");
        }
    }
}

// ---------------------------------------------------------------------------
// Budget assertion helpers
// ---------------------------------------------------------------------------

/// Reset the budget, run a closure, and return (cpu, mem) costs.
#[cfg(test)]
fn measure<T>(env: &Env, f: impl FnOnce() -> T) -> (u64, u64, T) {
    env.cost_estimate().budget().reset_unlimited();
    let result = f();
    let budget = env.cost_estimate().budget();
    (
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost(),
        result,
    )
}

/// Assert that cpu and mem are within the given thresholds.
#[cfg(test)]
fn assert_within(cpu: u64, mem: u64, max_cpu: u64, max_mem: u64, label: &str) {
    assert!(
        cpu <= max_cpu,
        "{label} CPU budget exceeded: {cpu} > {max_cpu}"
    );
    assert!(
        mem <= max_mem,
        "{label} memory budget exceeded: {mem} > {max_mem}"
    );
}

// ---------------------------------------------------------------------------
// Maximum budget thresholds (generous 3× safety margin above measured values;
// calibrate on first CI run if needed).
// ---------------------------------------------------------------------------

const MAX_CPU_INIT: u64 = 500_000;
const MAX_MEM_INIT: u64 = 500_000;

const MAX_CPU_ADD_ISSUER: u64 = 800_000;
const MAX_MEM_ADD_ISSUER: u64 = 600_000;

const MAX_CPU_ADD_CREDENTIAL_ROOT: u64 = 800_000;
const MAX_MEM_ADD_CREDENTIAL_ROOT: u64 = 600_000;

const MAX_CPU_SET_VERIFIER: u64 = 500_000;
const MAX_MEM_SET_VERIFIER: u64 = 400_000;

const MAX_CPU_REGISTER_SOURCE: u64 = 1_200_000;
const MAX_MEM_REGISTER_SOURCE: u64 = 1_000_000;

const MAX_CPU_REGISTER_SEAL: u64 = 1_500_000;
const MAX_MEM_REGISTER_SEAL: u64 = 1_200_000;

const MAX_CPU_REGISTER_ANONYMOUS: u64 = 1_500_000;
const MAX_MEM_REGISTER_ANONYMOUS: u64 = 1_000_000;

const MAX_CPU_REGISTER_ANONYMOUS_VERIFIED: u64 = 3_000_000;
const MAX_MEM_REGISTER_ANONYMOUS_VERIFIED: u64 = 2_000_000;

const MAX_CPU_REVOKE_PROOF: u64 = 800_000;
const MAX_MEM_REVOKE_PROOF: u64 = 600_000;

const MAX_CPU_REVOKE_PROOFS_WORST_CASE: u64 = 15_000_000;
const MAX_MEM_REVOKE_PROOFS_WORST_CASE: u64 = 10_000_000;

const MAX_CPU_GET_PROOF_STATUS: u64 = 500_000;
const MAX_MEM_GET_PROOF_STATUS: u64 = 400_000;

const MAX_CPU_GET_PROOF_ASSURANCE: u64 = 800_000;
const MAX_MEM_GET_PROOF_ASSURANCE: u64 = 600_000;

const MAX_CPU_REGISTER_SEAL_WORST_CASE: u64 = 2_000_000;
const MAX_MEM_REGISTER_SEAL_WORST_CASE: u64 = 1_500_000;

const MAX_CPU_REGISTER_SOURCE_BATCH: u64 = 1_200_000;
const MAX_MEM_REGISTER_SOURCE_BATCH: u64 = 1_000_000;

const MAX_CPU_VERIFY_SOURCE_BATCH_MAX_PROOF: u64 = 1_500_000;
const MAX_MEM_VERIFY_SOURCE_BATCH_MAX_PROOF: u64 = 1_000_000;


// ---------------------------------------------------------------------------
// Budget baseline tests (measurement)
// ---------------------------------------------------------------------------

#[test]
fn budget_init_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    let (cpu, mem, _) = measure(&env, || client.init(&admin));
    assert_within(cpu, mem, MAX_CPU_INIT, MAX_MEM_INIT, "init");
}

#[test]
fn budget_add_issuer_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.add_issuer(&admin, &issuer, &b32(&env, 0xAA))
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_ADD_ISSUER,
        MAX_MEM_ADD_ISSUER,
        "add_issuer",
    );
}

#[test]
fn budget_add_credential_root_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.add_credential_root(&admin, &b32(&env, 0xBB), &b32(&env, 0xCC))
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_ADD_CREDENTIAL_ROOT,
        MAX_MEM_ADD_CREDENTIAL_ROOT,
        "add_credential_root",
    );
}

#[test]
fn budget_set_verifier_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let verifier = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || client.set_verifier(&admin, &verifier));
    assert_within(
        cpu,
        mem,
        MAX_CPU_SET_VERIFIER,
        MAX_MEM_SET_VERIFIER,
        "set_verifier",
    );
}

#[test]
fn budget_register_source_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    let (cpu, mem, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x01),
            &b32(&env, 0x02),
            &b32(&env, 0x03),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SOURCE,
        MAX_MEM_REGISTER_SOURCE,
        "register_source",
    );
}

#[test]
fn budget_register_seal_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));

    let (cpu, mem, _) = measure(&env, || {
        client.register_seal(
            &issuer,
            &b32(&env, 0x11),
            &b32(&env, 0x12),
            &b32(&env, 0x13),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SEAL,
        MAX_MEM_REGISTER_SEAL,
        "register_seal",
    );
}

#[test]
fn budget_register_anonymous_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    client.add_credential_root(&admin, &b32(&env, 0xDD), &b32(&env, 0xEE));

    let (cpu, mem, _) = measure(&env, || {
        client.register_anonymous(
            &b32(&env, 0x21),
            &b32(&env, 0x22),
            &b32(&env, 0x23),
            &b32(&env, 0x24),
            &b32(&env, 0xDD),
            &proof_buf(&env),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_ANONYMOUS,
        MAX_MEM_REGISTER_ANONYMOUS,
        "register_anonymous",
    );
}

#[test]
fn budget_register_anonymous_verified_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let verifier_id = env.register(MockBudgetVerifier, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let video_hash = b32(&env, 0x31);
    let credential_root = b32(&env, 0x32);
    let nullifier = b32(&env, 0x33);

    client.init(&admin);
    client.set_verifier(&admin, &verifier_id);
    client.add_credential_root(&admin, &credential_root, &b32(&env, 0x34));

    let (cpu, mem, _) = measure(&env, || {
        client.register_anonymous_verified(
            &video_hash,
            &b32(&env, 0x35),
            &b32(&env, 0x36),
            &make_public_inputs(&env, &video_hash, &credential_root, &nullifier),
            &proof_buf(&env),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_ANONYMOUS_VERIFIED,
        MAX_MEM_REGISTER_ANONYMOUS_VERIFIED,
        "register_anonymous_verified",
    );
}

#[test]
fn budget_revoke_proof_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x41);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x42), &b32(&env, 0x43), &proof_id);

    let (cpu, mem, _) = measure(&env, || client.revoke_proof(&admin, &proof_id));
    assert_within(
        cpu,
        mem,
        MAX_CPU_REVOKE_PROOF,
        MAX_MEM_REVOKE_PROOF,
        "revoke_proof",
    );
}

#[test]
fn budget_revoke_proofs_worst_case() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    let mut proof_ids = SorobanVec::new(&env);
    for i in 0..MAX_REVOKE_PROOFS_BATCH_SIZE as u8 {
        let proof_id = b32(&env, 0x60 + i);
        client.register_source(
            &source,
            &b32(&env, 0x70 + i),
            &b32(&env, 0x80 + i),
            &proof_id,
        );
        proof_ids.push_back(proof_id);
    }

    let (cpu, mem, _) = measure(&env, || client.revoke_proofs(&admin, &proof_ids, &1));
    assert_within(
        cpu,
        mem,
        MAX_CPU_REVOKE_PROOFS_WORST_CASE,
        MAX_MEM_REVOKE_PROOFS_WORST_CASE,
        "revoke_proofs",
    );
}

#[test]
fn budget_get_proof_status_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x51);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x52), &b32(&env, 0x53), &proof_id);

    let (cpu, mem, status) = measure(&env, || client.get_proof_status(&proof_id));
    assert_eq!(status, ProofVerificationStatus::Valid);
    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_PROOF_STATUS,
        MAX_MEM_GET_PROOF_STATUS,
        "get_proof_status",
    );
}

#[test]
fn budget_get_proof_assurance_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x51);

    client.init(&admin);
    client.register_source(&source, &b32(&env, 0x52), &b32(&env, 0x53), &proof_id);

    let (cpu, mem, assurance) = measure(&env, || client.get_proof_assurance(&proof_id));
    assert!(assurance.is_some());
    let assurance = assurance.unwrap();
    assert_eq!(assurance.status, ProofVerificationStatus::Valid);
    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_PROOF_ASSURANCE,
        MAX_MEM_GET_PROOF_ASSURANCE,
        "get_proof_assurance",
    );
}

const MAX_CPU_GET_PROOF_STATUSES: u64 = 12_000_000;
const MAX_MEM_GET_PROOF_STATUSES: u64 = 3_000_000;

#[test]
fn budget_get_proof_statuses_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    // Register 10 proofs
    let mut proof_ids = SorobanVec::new(&env);
    for i in 0..10u8 {
        let proof_id = b32(&env, 0xA0 + i);
        client.register_source(
            &source,
            &b32(&env, 0xB0 + i),
            &b32(&env, 0xC0 + i),
            &proof_id,
        );
        proof_ids.push_back(proof_id);
    }

    // Pad to 100 ids for worst-case read (90 will be missing/not found)
    for i in 10..100u8 {
        let mut pad = [0xD0u8; 32];
        pad[1] = i;
        proof_ids.push_back(BytesN::from_array(&env, &pad));
    }

    // This baseline measures CPU/memory only. The 100-id read touches 101
    // ledger entries (100 keys + the contract instance), which exceeds the
    // mainnet invocation footprint limit (100), so disable that enforcement
    // for this env.
    env.cost_estimate().disable_resource_limits();

    let (cpu, mem, statuses) = measure(&env, || client.get_proof_statuses(&proof_ids));
    assert_eq!(statuses.len(), 100);
    assert_eq!(statuses.get(0).unwrap(), ProofVerificationStatus::Valid);
    assert_eq!(statuses.get(10).unwrap(), ProofVerificationStatus::NotFound);

    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_PROOF_STATUSES,
        MAX_MEM_GET_PROOF_STATUSES,
        "get_proof_statuses",
    );
}

const MAX_CPU_GET_STATUSES_BY_VIDEO: u64 = 15_000_000;
const MAX_MEM_GET_STATUSES_BY_VIDEO: u64 = 4_000_000;

#[test]
fn budget_get_statuses_by_video_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    // Register 10 proofs with known video hashes
    let mut video_hashes = SorobanVec::new(&env);
    for i in 0..10u8 {
        let proof_id = b32(&env, 0xA0 + i);
        let video_hash = b32(&env, 0xB0 + i);
        client.register_source(
            &source,
            &video_hash,
            &b32(&env, 0xC0 + i),
            &proof_id,
        );
        video_hashes.push_back(video_hash);
    }

    // Pad to 100 video hashes for worst-case read (90 will be missing/not found)
    for i in 10..100u8 {
        let mut pad = [0xD0u8; 32];
        pad[1] = i;
        video_hashes.push_back(BytesN::from_array(&env, &pad));
    }

    // Disable resource limits for the footprint
    env.cost_estimate().disable_resource_limits();

    let (cpu, mem, statuses) = measure(&env, || client.get_statuses_by_video(&video_hashes));
    assert_eq!(statuses.len(), 100);
    assert_eq!(statuses.get(0).unwrap(), ProofVerificationStatus::Valid);
    assert_eq!(statuses.get(10).unwrap(), ProofVerificationStatus::NotFound);

    assert_within(
        cpu,
        mem,
        MAX_CPU_GET_STATUSES_BY_VIDEO,
        MAX_MEM_GET_STATUSES_BY_VIDEO,
        "get_statuses_by_video",
    );
}

// ---------------------------------------------------------------------------
// Consecutive registration budget stability
// ---------------------------------------------------------------------------

/// Verify that repeated `register_source` calls consume a predictable budget
/// (no unbounded growth across registrations).
#[test]
fn budget_consecutive_registrations_stable() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // First registration
    let (cpu_first, mem_first, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x71),
            &b32(&env, 0x72),
            &b32(&env, 0x73),
        )
    });

    // Second registration
    let (cpu_second, mem_second, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x74),
            &b32(&env, 0x75),
            &b32(&env, 0x76),
        )
    });

    // Budget should be stable; allow up to 20% variance
    let cpu_ratio = if cpu_first == 0 {
        1.0
    } else {
        cpu_second as f64 / cpu_first as f64
    };
    let mem_ratio = if mem_first == 0 {
        1.0
    } else {
        mem_second as f64 / mem_first as f64
    };

    assert!(
        (0.8..=1.2).contains(&cpu_ratio),
        "register_source CPU budget not stable: first={cpu_first}, second={cpu_second}, ratio={cpu_ratio}"
    );
    assert!(
        (0.8..=1.2).contains(&mem_ratio),
        "register_source memory budget not stable: first={mem_first}, second={mem_second}, ratio={mem_ratio}"
    );
}

// ---------------------------------------------------------------------------
// Budget never exceeds limits under repeated operations
// ---------------------------------------------------------------------------

/// After 5 sequential `register_source` registrations, a 6th registration
/// still stays within the budget baseline (no memory leak or unbounded growth).
#[test]
fn budget_sixth_registration_within_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    client.init(&admin);

    // Register 5 proofs first
    for i in 0..5u8 {
        let base = 0x80 + i;
        client.register_source(
            &source,
            &b32(&env, base),
            &b32(&env, base + 1),
            &b32(&env, base + 2),
        );
    }

    // Measure the 6th
    let (cpu, mem, _) = measure(&env, || {
        client.register_source(
            &source,
            &b32(&env, 0x90),
            &b32(&env, 0x91),
            &b32(&env, 0x92),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SOURCE,
        MAX_MEM_REGISTER_SOURCE,
        "6th register_source",
    );
}

// ---------------------------------------------------------------------------
// Worst-case input scenario: maximal-size data in register_seal with TTL set
// ---------------------------------------------------------------------------

/// `register_seal` with TTL configured and worst-case metadata must stay within bounds.
/// This exercises all storage writes at once: Proof, Video, and the TTL computation.
#[test]
fn budget_register_seal_worst_case() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));
    // Set a non-zero TTL to exercise the expires_at computation path
    client.set_proof_ttl(&admin, &86_400u64);

    let (cpu, mem, _) = measure(&env, || {
        client.register_seal(
            &issuer,
            &b32(&env, 0x61),
            &b32(&env, 0x62),
            &b32(&env, 0x63),
        )
    });
    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_SEAL_WORST_CASE,
        MAX_MEM_REGISTER_SEAL_WORST_CASE,
        "register_seal worst-case",
    );
}

const MAX_CPU_COMMIT_RECEIPT: u64 = 10_000_000;
const MAX_MEM_COMMIT_RECEIPT: u64 = 300_000;

/// Baseline for `commit_receipt_digest` (#337): sha256 preimage, host
/// secp256r1 verification, one persistent write, one event.
#[test]
fn budget_receipt_commit_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_address = soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(
        &env,
        crate::test_receipt::CONTRACT1_STRKEY,
    ));
    let contract_id = env.register_at(&contract_address, HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);
    client.register_source(
        &source,
        &b32(&env, 0x61),
        &b32(&env, 0x62),
        &b32(&env, 0x11),
    );
    client.add_receipt_signer(
        &admin,
        &BytesN::from_array(&env, &crate::test_receipt::PUB1),
    );

    let (cpu, mem, record) = measure(&env, || {
        client.commit_receipt_digest(
            &source,
            &b32(&env, 0x11),
            &BytesN::from_array(&env, &crate::test_receipt::DIGEST1),
            &BytesN::from_array(&env, &crate::test_receipt::PUB1),
            &BytesN::from_array(&env, &crate::test_receipt::SIG_A),
        )
    });
    assert_eq!(record.tier, TIER_CONSISTENT_SOURCE);
    assert_within(
        cpu,
        mem,
        MAX_CPU_COMMIT_RECEIPT,
        MAX_MEM_COMMIT_RECEIPT,
        "commit_receipt_digest",
    );
}

const MAX_CPU_LIST_LINEAGE_CHILDREN_PAGE: u64 = 6_000_000;
const MAX_MEM_LIST_LINEAGE_CHILDREN_PAGE: u64 = 1_500_000;

/// Baseline for `list_lineage_children` at `MAX_LINEAGE_CHILDREN_PAGE` (50 entries).
///
/// Registers enough children for a full page and records CPU/memory for one
/// `list_lineage_children` call, asserting it stays within resource thresholds.
#[test]
fn budget_list_lineage_children_full_page_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = b32(&env, 0x10);

    client.init(&admin);
    client.register_source(&actor, &b32(&env, 0x11), &b32(&env, 0x12), &parent);

    // Register MAX_LINEAGE_CHILDREN_PAGE (50) children
    let mut expected_children = SorobanVec::new(&env);
    for i in 0..MAX_LINEAGE_CHILDREN_PAGE {
        let mut child_arr = [0x20u8; 32];
        child_arr[0] = (i & 0xFF) as u8;
        child_arr[1] = ((i >> 8) & 0xFF) as u8;
        let child = BytesN::from_array(&env, &child_arr);

        let mut manifest_arr = [0x30u8; 32];
        manifest_arr[0] = (i & 0xFF) as u8;
        manifest_arr[1] = ((i >> 8) & 0xFF) as u8;
        let manifest = BytesN::from_array(&env, &manifest_arr);

        client.register_lineage(
            &actor,
            &SorobanVec::from_array(&env, [parent.clone()]),
            &manifest,
            &Symbol::new(&env, "crop"),
            &child,
            &1,
        );
        expected_children.push_back(child);
    }

    assert_eq!(
        client.get_lineage_children_count(&parent),
        MAX_LINEAGE_CHILDREN_PAGE
    );

    // Measure reading a full page of MAX_LINEAGE_CHILDREN_PAGE entries
    let (cpu, mem, page) = measure(&env, || {
        client.list_lineage_children(&parent, &0, &MAX_LINEAGE_CHILDREN_PAGE)
    });

    assert_eq!(page.total, MAX_LINEAGE_CHILDREN_PAGE);
    assert_eq!(page.next_offset, MAX_LINEAGE_CHILDREN_PAGE);
    assert_eq!(page.children.len(), MAX_LINEAGE_CHILDREN_PAGE);
    assert_eq!(page.children, expected_children);

    assert_within(
        cpu,
        mem,
        MAX_CPU_LIST_LINEAGE_CHILDREN_PAGE,
        MAX_MEM_LIST_LINEAGE_CHILDREN_PAGE,
        "list_lineage_children full page",
    );
}

const MAX_CPU_LIST_CREDENTIAL_ROOTS_PAGE: u64 = 4_000_000;
const MAX_MEM_LIST_CREDENTIAL_ROOTS_PAGE: u64 = 1_500_000;

/// Baseline for `list_credential_roots` at `MAX_CREDENTIAL_ROOTS_PAGE` (25 entries).
#[test]
fn budget_list_credential_roots_full_page_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    for i in 1..=MAX_CREDENTIAL_ROOTS_PAGE {
        client.add_credential_root(&admin, &b32(&env, i as u8), &b32(&env, 0xEE));
    }

    assert_eq!(
        client.get_credential_root_count(),
        MAX_CREDENTIAL_ROOTS_PAGE
    );

    let (cpu, mem, page) = measure(&env, || {
        client.list_credential_roots(&0, &MAX_CREDENTIAL_ROOTS_PAGE)
    });

    assert_eq!(page.roots.len(), MAX_CREDENTIAL_ROOTS_PAGE);
    assert_eq!(page.next_cursor, None);

    assert_within(
        cpu,
        mem,
        MAX_CPU_LIST_CREDENTIAL_ROOTS_PAGE,
        MAX_MEM_LIST_CREDENTIAL_ROOTS_PAGE,
        "list_credential_roots full page",
    );
}

// ---------------------------------------------------------------------------
// Dispute budget baselines (#dispute)
// ---------------------------------------------------------------------------

const MAX_CPU_OPEN_DISPUTE: u64 = 1_500_000;
const MAX_MEM_OPEN_DISPUTE: u64 = 1_000_000;

const MAX_CPU_OPEN_DISPUTE_WORST_CASE: u64 = 2_000_000;
const MAX_MEM_OPEN_DISPUTE_WORST_CASE: u64 = 1_200_000;

const MAX_CPU_RESPOND_DISPUTE: u64 = 1_500_000;
const MAX_MEM_RESPOND_DISPUTE: u64 = 1_000_000;

const MAX_CPU_RESPOND_DISPUTE_WORST_CASE: u64 = 2_000_000;
const MAX_MEM_RESPOND_DISPUTE_WORST_CASE: u64 = 1_200_000;

const MAX_CPU_SUPERSEDE_DISPUTE: u64 = 1_500_000;
const MAX_MEM_SUPERSEDE_DISPUTE: u64 = 1_000_000;

const MAX_CPU_SUPERSEDE_DISPUTE_WORST_CASE: u64 = 2_000_000;
const MAX_MEM_SUPERSEDE_DISPUTE_WORST_CASE: u64 = 1_200_000;

/// Baseline for `open_dispute` on an existing proof record.
#[test]
fn budget_open_dispute_baseline() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let reporter = Address::generate(&env);

    client.init(&admin);

    let proof_id = b32(&env, 0x11);
    client.register_source(&source, &b32(&env, 0x12), &b32(&env, 0x13), &proof_id);

    let dispute_id = b32(&env, 0xD1);
    let reporter_hash = b32(&env, 0xE1);
    let commitment_hash = b32(&env, 0xC1);

    let (cpu, mem, rec) = measure(&env, || {
        client.open_dispute(
            &reporter,
            &reporter_hash,
            &dispute_id,
            &proof_id,
            &DisputeReason::ContentError,
            &commitment_hash,
        )
    });

    assert_eq!(rec.status, DisputeStatus::Open);
    assert_eq!(rec.dispute_id, dispute_id);
    assert_eq!(client.get_open_dispute_count(&proof_id), 1);

    assert_within(
        cpu,
        mem,
        MAX_CPU_OPEN_DISPUTE,
        MAX_MEM_OPEN_DISPUTE,
        "open_dispute",
    );
}

/// Worst-case baseline for `open_dispute`: opening the final dispute allowed by
/// `MAX_OPEN_DISPUTES_PER_PROOF` when the reporter also has existing open disputes.
#[test]
fn budget_open_dispute_worst_case() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let reporter = Address::generate(&env);

    client.init(&admin);

    let proof_id = b32(&env, 0x21);
    client.register_source(&source, &b32(&env, 0x22), &b32(&env, 0x23), &proof_id);

    // Fill up to MAX_OPEN_DISPUTES_PER_PROOF - 1 (3 open disputes) with different reporters
    for i in 0..(MAX_OPEN_DISPUTES_PER_PROOF - 1) {
        let rep = Address::generate(&env);
        let mut d_arr = [0xD0u8; 32];
        d_arr[0] = i as u8;
        let mut r_arr = [0xE0u8; 32];
        r_arr[0] = i as u8;
        let mut c_arr = [0xC0u8; 32];
        c_arr[0] = i as u8;

        client.open_dispute(
            &rep,
            &BytesN::from_array(&env, &r_arr),
            &BytesN::from_array(&env, &d_arr),
            &proof_id,
            &DisputeReason::Other,
            &BytesN::from_array(&env, &c_arr),
        );
    }
    assert_eq!(
        client.get_open_dispute_count(&proof_id),
        MAX_OPEN_DISPUTES_PER_PROOF - 1
    );

    // Advance timestamp past reporter cooldown to test opening a dispute with an active reporter
    let ts = env.ledger().timestamp();
    env.ledger().set_timestamp(ts + REPORTER_COOLDOWN_SECS + 1);

    let target_dispute_id = b32(&env, 0xDF);
    let target_reporter_hash = b32(&env, 0xEF);
    let target_commitment = b32(&env, 0xCF);

    let (cpu, mem, rec) = measure(&env, || {
        client.open_dispute(
            &reporter,
            &target_reporter_hash,
            &target_dispute_id,
            &proof_id,
            &DisputeReason::PrivacyViolation,
            &target_commitment,
        )
    });

    assert_eq!(rec.status, DisputeStatus::Open);
    assert_eq!(
        client.get_open_dispute_count(&proof_id),
        MAX_OPEN_DISPUTES_PER_PROOF
    );

    assert_within(
        cpu,
        mem,
        MAX_CPU_OPEN_DISPUTE_WORST_CASE,
        MAX_MEM_OPEN_DISPUTE_WORST_CASE,
        "open_dispute worst-case",
    );
}

/// Baseline for `respond_dispute`: responding to an open dispute.
#[test]
fn budget_respond_dispute_baseline() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let reporter = Address::generate(&env);

    client.init(&admin);

    let proof_id = b32(&env, 0x31);
    client.register_source(&source, &b32(&env, 0x32), &b32(&env, 0x33), &proof_id);

    let dispute_id = b32(&env, 0xD3);
    client.open_dispute(
        &reporter,
        &b32(&env, 0xE3),
        &dispute_id,
        &proof_id,
        &DisputeReason::ContentError,
        &b32(&env, 0xC3),
    );

    let response_commitment = b32(&env, 0xB3);
    let (cpu, mem, rec) = measure(&env, || {
        client.respond_dispute(&source, &dispute_id, &response_commitment)
    });

    assert_eq!(rec.status, DisputeStatus::Responded);
    assert_eq!(rec.response_commitment, Some(response_commitment));

    assert_within(
        cpu,
        mem,
        MAX_CPU_RESPOND_DISPUTE,
        MAX_MEM_RESPOND_DISPUTE,
        "respond_dispute",
    );
}

/// Worst-case baseline for `respond_dispute`: responding to a dispute when the proof has
/// multiple active open disputes and proof record with full fields.
#[test]
fn budget_respond_dispute_worst_case() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    let proof_id = b32(&env, 0x41);
    client.register_source(&source, &b32(&env, 0x42), &b32(&env, 0x43), &proof_id);

    let target_dispute_id = b32(&env, 0x4D);

    // Open max open disputes on this proof
    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let rep = Address::generate(&env);
        let mut d_arr = [0x4Du8; 32];
        d_arr[0] = i as u8;
        let dispute_id = if i == 0 {
            target_dispute_id.clone()
        } else {
            BytesN::from_array(&env, &d_arr)
        };
        let mut r_arr = [0x4Eu8; 32];
        r_arr[0] = i as u8;
        let mut c_arr = [0x4Cu8; 32];
        c_arr[0] = i as u8;

        client.open_dispute(
            &rep,
            &BytesN::from_array(&env, &r_arr),
            &dispute_id,
            &proof_id,
            &DisputeReason::ContentError,
            &BytesN::from_array(&env, &c_arr),
        );
    }

    let response_commitment = b32(&env, 0xBA);
    let (cpu, mem, rec) = measure(&env, || {
        client.respond_dispute(&source, &target_dispute_id, &response_commitment)
    });

    assert_eq!(rec.status, DisputeStatus::Responded);
    assert_within(
        cpu,
        mem,
        MAX_CPU_RESPOND_DISPUTE_WORST_CASE,
        MAX_MEM_RESPOND_DISPUTE_WORST_CASE,
        "respond_dispute worst-case",
    );
}

/// Baseline for `supersede_dispute`: resolving a dispute by superseding with a new proof.
#[test]
fn budget_supersede_dispute_baseline() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);
    let reporter = Address::generate(&env);

    client.init(&admin);

    let spid = b32(&env, 0x51);
    client.register_source(&source, &b32(&env, 0x52), &b32(&env, 0x53), &spid);

    let sealid = b32(&env, 0x54);
    client.register_source(&source, &b32(&env, 0x55), &b32(&env, 0x56), &sealid);

    let dispute_id = b32(&env, 0xD5);
    client.open_dispute(
        &reporter,
        &b32(&env, 0xE5),
        &dispute_id,
        &spid,
        &DisputeReason::ContentError,
        &b32(&env, 0xC5),
    );

    let (cpu, mem, rec) = measure(&env, || {
        client.supersede_dispute(&admin, &dispute_id, &sealid)
    });

    assert_eq!(rec.status, DisputeStatus::Superseded);
    assert_eq!(rec.superseded_by, Some(sealid));
    assert_eq!(client.get_open_dispute_count(&spid), 0);

    assert_within(
        cpu,
        mem,
        MAX_CPU_SUPERSEDE_DISPUTE,
        MAX_MEM_SUPERSEDE_DISPUTE,
        "supersede_dispute",
    );
}

/// Worst-case baseline for `supersede_dispute`: superseding on a proof where other open
/// disputes exist and reverse index checks must verify depth-1 cycle avoidance.
#[test]
fn budget_supersede_dispute_worst_case() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let source = Address::generate(&env);

    client.init(&admin);

    let spid = b32(&env, 0x61);
    client.register_source(&source, &b32(&env, 0x62), &b32(&env, 0x63), &spid);

    let correcting_proof = b32(&env, 0x64);
    client.register_source(&source, &b32(&env, 0x65), &b32(&env, 0x66), &correcting_proof);

    let target_dispute_id = b32(&env, 0x6D);

    // Open multiple disputes on spid
    for i in 0..MAX_OPEN_DISPUTES_PER_PROOF {
        let rep = Address::generate(&env);
        let mut d_arr = [0x6Du8; 32];
        d_arr[0] = i as u8;
        let dispute_id = if i == 0 {
            target_dispute_id.clone()
        } else {
            BytesN::from_array(&env, &d_arr)
        };
        let mut r_arr = [0x6Eu8; 32];
        r_arr[0] = i as u8;
        let mut c_arr = [0x6Cu8; 32];
        c_arr[0] = i as u8;

        client.open_dispute(
            &rep,
            &BytesN::from_array(&env, &r_arr),
            &dispute_id,
            &spid,
            &DisputeReason::ContentError,
            &BytesN::from_array(&env, &c_arr),
        );
    }

    let (cpu, mem, rec) = measure(&env, || {
        client.supersede_dispute(&admin, &target_dispute_id, &correcting_proof)
    });

    assert_eq!(rec.status, DisputeStatus::Superseded);
    assert_eq!(rec.superseded_by, Some(correcting_proof));

    assert_within(
        cpu,
        mem,
        MAX_CPU_SUPERSEDE_DISPUTE_WORST_CASE,
        MAX_MEM_SUPERSEDE_DISPUTE_WORST_CASE,
        "supersede_dispute worst-case",
    );
}

// ---------------------------------------------------------------------------
// Lineage budget baselines (#333, #332)
// ---------------------------------------------------------------------------

const MAX_CPU_REGISTER_LINEAGE: u64 = 2_000_000;
const MAX_MEM_REGISTER_LINEAGE: u64 = 1_000_000;

const MAX_CPU_REGISTER_LINEAGE_WORST_CASE: u64 = 3_500_000;
const MAX_MEM_REGISTER_LINEAGE_WORST_CASE: u64 = 1_500_000;

const MAX_CPU_LIST_LINEAGE_CHILDREN_BASELINE: u64 = 1_500_000;
const MAX_MEM_LIST_LINEAGE_CHILDREN_BASELINE: u64 = 800_000;

/// Baseline for `register_lineage`: single parent proof, depth 1.
#[test]
fn budget_register_lineage_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = b32(&env, 0x71);

    client.init(&admin);
    client.register_source(&actor, &b32(&env, 0x72), &b32(&env, 0x73), &parent);

    let output = b32(&env, 0x74);
    let manifest = b32(&env, 0x75);
    let parents = SorobanVec::from_array(&env, [parent]);

    let (cpu, mem, record) = measure(&env, || {
        client.register_lineage(
            &actor,
            &parents,
            &manifest,
            &Symbol::new(&env, "crop"),
            &output,
            &1,
        )
    });

    assert_eq!(record.output_digest, output);
    assert_eq!(record.depth, 1);
    assert_eq!(record.parent_proof_ids.len(), 1);
    assert_eq!(record.parent_commitments.len(), 1);

    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_LINEAGE,
        MAX_MEM_REGISTER_LINEAGE,
        "register_lineage",
    );
}

/// Worst-case baseline for `register_lineage`: maximal fan-out (`MAX_LINEAGE_FANOUT = 4`)
/// and maximal depth chain (`MAX_LINEAGE_DEPTH = 4`).
#[test]
fn budget_register_lineage_worst_case() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);

    client.init(&admin);

    // Build a lineage chain up to depth 3 so the 4th derivative reaches MAX_LINEAGE_DEPTH (4)
    let root = b32(&env, 0x81);
    client.register_source(&actor, &b32(&env, 0x82), &b32(&env, 0x83), &root);

    let d1 = b32(&env, 0x84);
    client.register_lineage(
        &actor,
        &SorobanVec::from_array(&env, [root]),
        &b32(&env, 0x85),
        &Symbol::new(&env, "derive1"),
        &d1,
        &1,
    );

    let d2 = b32(&env, 0x86);
    client.register_lineage(
        &actor,
        &SorobanVec::from_array(&env, [d1]),
        &b32(&env, 0x87),
        &Symbol::new(&env, "derive2"),
        &d2,
        &2,
    );

    let d3 = b32(&env, 0x88);
    client.register_lineage(
        &actor,
        &SorobanVec::from_array(&env, [d2]),
        &b32(&env, 0x89),
        &Symbol::new(&env, "derive3"),
        &d3,
        &3,
    );

    // Create 3 additional distinct registered parent proofs to satisfy MAX_LINEAGE_FANOUT (4)
    let p_extra1 = b32(&env, 0x91);
    client.register_source(&actor, &b32(&env, 0x92), &b32(&env, 0x93), &p_extra1);

    let p_extra2 = b32(&env, 0x94);
    client.register_source(&actor, &b32(&env, 0x95), &b32(&env, 0x96), &p_extra2);

    let p_extra3 = b32(&env, 0x97);
    client.register_source(&actor, &b32(&env, 0x98), &b32(&env, 0x99), &p_extra3);

    let mut parent_set = SorobanVec::new(&env);
    parent_set.push_back(d3);
    parent_set.push_back(p_extra1);
    parent_set.push_back(p_extra2);
    parent_set.push_back(p_extra3);
    assert_eq!(parent_set.len(), MAX_LINEAGE_FANOUT);

    let output_target = b32(&env, 0x9A);
    let manifest_target = b32(&env, 0x9B);

    let (cpu, mem, record) = measure(&env, || {
        client.register_lineage(
            &actor,
            &parent_set,
            &manifest_target,
            &Symbol::new(&env, "composite"),
            &output_target,
            &MAX_LINEAGE_DEPTH,
        )
    });

    assert_eq!(record.output_digest, output_target);
    assert_eq!(record.depth, MAX_LINEAGE_DEPTH);
    assert_eq!(record.parent_proof_ids.len(), MAX_LINEAGE_FANOUT);
    assert_eq!(record.parent_commitments.len(), MAX_LINEAGE_FANOUT);

    assert_within(
        cpu,
        mem,
        MAX_CPU_REGISTER_LINEAGE_WORST_CASE,
        MAX_MEM_REGISTER_LINEAGE_WORST_CASE,
        "register_lineage worst-case",
    );
}

/// Baseline for `list_lineage_children` with a small/single child read.
#[test]
fn budget_list_lineage_children_baseline() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let actor = Address::generate(&env);
    let parent = b32(&env, 0xA1);

    client.init(&admin);
    client.register_source(&actor, &b32(&env, 0xA2), &b32(&env, 0xA3), &parent);

    let child = b32(&env, 0xA4);
    client.register_lineage(
        &actor,
        &SorobanVec::from_array(&env, [parent.clone()]),
        &b32(&env, 0xA5),
        &Symbol::new(&env, "crop"),
        &child,
        &1,
    );

    assert_eq!(client.get_lineage_children_count(&parent), 1);

    let (cpu, mem, page) = measure(&env, || {
        client.list_lineage_children(&parent, &0, &1)
    });

    assert_eq!(page.total, 1);
    assert_eq!(page.next_offset, 1);
    assert_eq!(page.children.len(), 1);
    assert_eq!(page.children.get(0).unwrap(), child);

    assert_within(
        cpu,
        mem,
        MAX_CPU_LIST_LINEAGE_CHILDREN_BASELINE,
        MAX_MEM_LIST_LINEAGE_CHILDREN_BASELINE,
        "list_lineage_children baseline",
    );
}

