// Bounded redacted-derivative lineage circuit. All witness media and region
// data remains private; only commitments use the public verifier frame.
global CURRENT_CIRCUIT_VERSION: u32 = 1;
global MAX_CHUNKS: u32 = 4;
global REDACTION_WITNESS_V1: Field = 0x484152504f4352415445535f524544414354494f4e5f5631;
global PARENT_ACCUMULATOR_V1: Field = 0x504152454e545f414343554d554c41544f525f5631;
global OUTPUT_COMMITMENT_V1: Field = 0x4f55545055545f434f4d4d49544d454e545f5631;

fn allowed_operation(operation: Field) -> bool {
    (operation == 1) | (operation == 2) | (operation == 3) | (operation == 4) | (operation == 5)
}

fn parent_accumulator(chunks: [Field; MAX_CHUNKS]) -> Field {
    let mut accumulator = std::hash::pedersen_hash([PARENT_ACCUMULATOR_V1]);
    for index in 0..MAX_CHUNKS {
        accumulator = std::hash::pedersen_hash([accumulator, index as Field, chunks[index]]);
    }
    accumulator
}

fn compute_output_commitment(
    parent_commitment: Field,
    operation_type: Field,
    parameters_digest: Field,
    replay_binding: Field,
    blinding_factor: Field,
    visible_chunks: [Field; MAX_CHUNKS],
    removed_descriptors: [Field; MAX_CHUNKS],
) -> Field {
    let mut output = std::hash::pedersen_hash([
        OUTPUT_COMMITMENT_V1, parent_commitment, operation_type, parameters_digest, replay_binding, blinding_factor,
    ]);
    for index in 0..MAX_CHUNKS {
        output = std::hash::pedersen_hash([output, index as Field, visible_chunks[index], removed_descriptors[index]]);
    }
    output
}

fn main(
    parent_chunks: [Field; MAX_CHUNKS],
    visible_chunks: [Field; MAX_CHUNKS],
    removed_descriptors: [Field; MAX_CHUNKS],
    parameters_digest: Field,
    blinding_factor: Field,
    parent_commitment: pub Field,
    output_commitment: pub Field,
    operation_type: pub Field,
    replay_binding: pub Field,
    domain_tag: pub Field,
) {
    assert(CURRENT_CIRCUIT_VERSION == 1, "circuit version mismatch");
    assert(allowed_operation(operation_type), "operation is not allowed");
    assert(parent_accumulator(parent_chunks) == parent_commitment, "parent commitment mismatch");

    let mut output = std::hash::pedersen_hash([
        OUTPUT_COMMITMENT_V1, parent_commitment, operation_type, parameters_digest, replay_binding, blinding_factor,
    ]);
    for index in 0..MAX_CHUNKS {
        if removed_descriptors[index] == 0 {
            assert(visible_chunks[index] == parent_chunks[index], "visible chunk altered");
        } else {
            // A removed region has no visible chunk. Without this constraint an
            // attacker could label an arbitrary replacement as "removed" and
            // commit it as visible derivative content.
            assert(visible_chunks[index] == 0, "removed chunk must be hidden");
        }
        output = std::hash::pedersen_hash([output, index as Field, visible_chunks[index], removed_descriptors[index]]);
    }
    assert(output == output_commitment, "output commitment mismatch");
    assert(domain_tag == REDACTION_WITNESS_V1, "domain tag mismatch");
}

#[test]
fn valid_crop_lineage() {
    let parents = [11, 12, 13, 14];
    let visible = [11, 12, 0, 0];
    let removed = [0, 0, 101, 102];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test]
fn valid_blur_lineage() {
    let parents = [21, 22, 23, 24];
    let visible = [21, 0, 23, 24];
    let removed = [0, 201, 0, 0];
    let params: Field = 88;
    let replay: Field = 66;
    let blinding: Field = 44;
    let op: Field = 3;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test]
fn valid_redact_lineage() {
    let parents = [31, 32, 33, 34];
    let visible = [31, 32, 0, 34];
    let removed = [0, 0, 301, 0];
    let params: Field = 77;
    let replay: Field = 55;
    let blinding: Field = 33;
    let op: Field = 4;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test]
fn valid_transcode_lineage() {
    let parents = [41, 42, 43, 44];
    let visible = [41, 42, 43, 44];
    let removed = [0, 0, 0, 0];
    let params: Field = 66;
    let replay: Field = 44;
    let blinding: Field = 22;
    let op: Field = 2;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test]
fn valid_compose_lineage() {
    let parents = [51, 52, 53, 54];
    let visible = [51, 52, 53, 0];
    let removed = [0, 0, 0, 501];
    let params: Field = 55;
    let replay: Field = 33;
    let blinding: Field = 11;
    let op: Field = 5;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "parent commitment mismatch")]
fn rejects_reordered_chunks() {
    let parents = [11, 12, 13, 14];
    let bad_parents = [12, 11, 13, 14];
    let removed = [0, 0, 0, 0];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let parent = parent_accumulator(parents);
    let bad_parent = parent_accumulator(bad_parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, parents, removed);
    main(parents, parents, removed, params, blinding, bad_parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "parent commitment mismatch")]
fn rejects_crop_substitution() {
    let genuine_parents = [11, 12, 13, 14];
    let substituted_parents = [99, 12, 13, 14];
    let removed = [0, 0, 0, 0];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let genuine_parent = parent_accumulator(genuine_parents);
    let output = compute_output_commitment(genuine_parent, op, params, replay, blinding, genuine_parents, removed);
    main(substituted_parents, genuine_parents, removed, params, blinding, genuine_parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "visible chunk altered")]
fn rejects_altered_visible_region() {
    let parents = [11, 12, 13, 14];
    let tampered_visible = [11, 99, 13, 14];
    let removed = [0, 0, 0, 0];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, tampered_visible, removed);
    main(parents, tampered_visible, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "removed chunk must be hidden")]
fn rejects_replacement_disguised_as_removed_region() {
    let parents = [11, 12, 13, 14];
    let replacement = [11, 99, 13, 14];
    let removed = [0, 401, 0, 0];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 4;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, replacement, removed);
    main(parents, replacement, removed, params, blinding, parent, output, op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "output commitment mismatch")]
fn rejects_replay_different_claim() {
    let parents = [11, 12, 13, 14];
    let visible = [11, 12, 0, 0];
    let removed = [0, 0, 101, 102];
    let params: Field = 99;
    let replay: Field = 77;
    let bad_replay: Field = 88;
    let blinding: Field = 55;
    let op: Field = 1;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, bad_replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "operation is not allowed")]
fn rejects_unknown_operation() {
    let parents = [1, 2, 3, 4];
    let removed = [0, 0, 0, 0];
    let params: Field = 1;
    let replay: Field = 2;
    let blinding: Field = 3;
    let bad_op: Field = 9;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, bad_op, params, replay, blinding, parents, removed);
    main(parents, parents, removed, params, blinding, parent, output, bad_op, replay, REDACTION_WITNESS_V1);
}

#[test(should_fail_with = "domain tag mismatch")]
fn rejects_wrong_domain_tag() {
    let parents = [11, 12, 13, 14];
    let visible = [11, 12, 0, 0];
    let removed = [0, 0, 101, 102];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let bad_tag: Field = 999;
    let parent = parent_accumulator(parents);
    let output = compute_output_commitment(parent, op, params, replay, blinding, visible, removed);
    main(parents, visible, removed, params, blinding, parent, output, op, replay, bad_tag);
}
#[test(should_fail_with = "parent commitment mismatch")]
fn rejects_wrong_parent() {
    let actual_parents = [11, 12, 13, 14];
    let unrelated_parents = [201, 202, 203, 204];
    let removed = [0, 0, 0, 0];
    let params: Field = 99;
    let replay: Field = 77;
    let blinding: Field = 55;
    let op: Field = 1;
    let actual_parent = parent_accumulator(actual_parents);
    let unrelated_parent = parent_accumulator(unrelated_parents);
    let output = compute_output_commitment(actual_parent, op, params, replay, blinding, actual_parents, removed);
    main(actual_parents, actual_parents, removed, params, blinding, unrelated_parent, output, op, replay, REDACTION_WITNESS_V1);
}
