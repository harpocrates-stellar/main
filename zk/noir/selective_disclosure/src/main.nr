use std::hash::pedersen_hash;

global MAX_ATTRIBUTES: u32 = 16;
global MAX_PREDICATES: u32 = 8;
global MAX_SET_MEMBERS: u32 = 8;
global MAX_INTERVAL_CLAUSES: u32 = 4;
global CURRENT_CIRCUIT_VERSION: u32 = 1;

global EQ_PREDICATE_TYPE: Field = 0;
global SET_MEMBERSHIP_PREDICATE_TYPE: Field = 1;
global RANGE_PREDICATE_TYPE: Field = 2;
global INTERVAL_INTERSECTION_PREDICATE_TYPE: Field = 3;

global TWO_POW_64: Field = 0x10000000000000000;
global TWO_POW_128: Field = 0x100000000000000000000000000000000;
global U64_MAX: u64 = 0xffffffffffffffff;

fn eq_predicate_type() -> Field {
    EQ_PREDICATE_TYPE
}

fn set_membership_predicate_type() -> Field {
    SET_MEMBERSHIP_PREDICATE_TYPE
}

fn range_predicate_type() -> Field {
    RANGE_PREDICATE_TYPE
}

fn interval_intersection_predicate_type() -> Field {
    INTERVAL_INTERSECTION_PREDICATE_TYPE
}

fn assert_valid_predicate_type(predicate_type: Field, is_active: bool) {
    let is_eq = predicate_type == eq_predicate_type();
    let is_set = predicate_type == set_membership_predicate_type();
    let is_range = predicate_type == range_predicate_type();
    let is_interval = predicate_type == interval_intersection_predicate_type();
    assert(
        !is_active | (is_eq | is_set | is_range | is_interval),
        "unsupported predicate type",
    );
}

fn pack_canonical_interval_conjunction(
    lower: u64,
    upper: u64,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> Field {
    let lo_flag: Field = if lower_inclusive { 1 } else { 0 };
    let hi_flag: Field = if upper_inclusive { 2 } else { 0 };
    let canonical_flags = lo_flag + hi_flag;
    (lower as Field) + (upper as Field) * TWO_POW_64 + canonical_flags * TWO_POW_128
}

fn attr_commitment(value: Field, blinding: Field) -> Field {
    pedersen_hash([value, blinding])
}

fn compute_credential_root(
    commitments: [Field; MAX_ATTRIBUTES],
    num_attributes: u32,
) -> Field {
    let mut current = commitments[0];
    for i in 1..MAX_ATTRIBUTES {
        let next = pedersen_hash([current, commitments[i]]);
        if i < num_attributes {
            current = next;
        }
    }
    current
}

fn verify_predicate(
    predicate_type: Field,
    attr_value: Field,
    public_value: Field,
    set_values: [Field; MAX_SET_MEMBERS],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
    is_active: bool,
) {
    let is_eq = predicate_type == eq_predicate_type();
    let is_set = predicate_type == set_membership_predicate_type();
    let is_range = predicate_type == range_predicate_type();
    let is_interval = predicate_type == interval_intersection_predicate_type();

    assert(
        !is_active | (is_eq | is_set | is_range | is_interval),
        "unsupported",
    );

    let eq_valid = attr_value == public_value;
    assert(!(is_active & is_eq) | eq_valid, "malformed");

    let mut set_found = false;
    for i in 0..MAX_SET_MEMBERS {
        let matches = set_values[i] == attr_value;
        let in_range = i < set_len;
        set_found = set_found | (matches & in_range);
    }
    assert(!(is_active & is_set) | set_found, "malformed");

    // Only apply 64-bit integer casts when an ordered predicate (Range or IntervalIntersection)
    // is active, preserving full BN254 Field support for Equality and SetMembership.
    let needs_ordered_cmp = is_active & (is_range | is_interval);
    let bounded_attr = if needs_ordered_cmp { attr_value } else { 0 };
    let bounded_lo = if needs_ordered_cmp { lower_bound } else { 0 };
    let bounded_hi = if needs_ordered_cmp { upper_bound } else { 0 };
    let attr_u64 = bounded_attr as u64;
    let lower_u64 = bounded_lo as u64;
    let upper_u64 = bounded_hi as u64;
    assert(!needs_ordered_cmp | ((attr_u64 as Field) == bounded_attr), "malformed");
    assert(!needs_ordered_cmp | ((lower_u64 as Field) == bounded_lo), "malformed");
    assert(!needs_ordered_cmp | ((upper_u64 as Field) == bounded_hi), "malformed");

    let range_lower_valid = attr_u64 >= lower_u64;
    let range_upper_valid = attr_u64 <= upper_u64;
    assert(!(is_active & is_range) | range_lower_valid, "malformed");
    assert(!(is_active & is_range) | range_upper_valid, "malformed");

    // Canonical conjunction of inclusive/exclusive interval bounds (predicate_type == 3).
    // Encoding:
    //   - set_len = num_clauses | (clause_mask << 8), with 1 <= num_clauses <= 4
    //   - set_values = [lo_0, hi_0, lo_1, hi_1, lo_2, hi_2, lo_3, hi_3]
    //   - bit (2 * j) of clause_mask = lower_inclusive_j, bit (2 * j + 1) = upper_inclusive_j
    //   - lower_bound, upper_bound = canonical reduced [L*, U*]
    //   - public_value = L* + U* * 2^64 + canonical_flags * 2^128 (bound into predicate_commitment)
    let check_interval = is_active & is_interval;
    let raw_meta: u32 = if check_interval { set_len } else { 1 };
    let num_clauses: u32 = raw_meta & 255;
    let clause_mask: u32 = raw_meta >> 8;

    assert(!check_interval | (num_clauses >= 1), "malformed");
    assert(!check_interval | (num_clauses <= MAX_INTERVAL_CLAUSES), "oversized");
    assert(!check_interval | (clause_mask < 256), "malformed");

    let inc_flags: [bool; 8] = [
        (clause_mask & 1) != 0,
        (clause_mask & 2) != 0,
        (clause_mask & 4) != 0,
        (clause_mask & 8) != 0,
        (clause_mask & 16) != 0,
        (clause_mask & 32) != 0,
        (clause_mask & 64) != 0,
        (clause_mask & 128) != 0,
    ];

    let mut clause_los: [u64; MAX_INTERVAL_CLAUSES] = [0; MAX_INTERVAL_CLAUSES];
    let mut clause_his: [u64; MAX_INTERVAL_CLAUSES] = [0; MAX_INTERVAL_CLAUSES];
    for j in 0..MAX_INTERVAL_CLAUSES {
        let active_clause = check_interval & (j < num_clauses);
        let inactive_clause = check_interval & (j >= num_clauses);
        assert(
            !inactive_clause | ((!inc_flags[2 * j]) & (!inc_flags[2 * j + 1])),
            "malformed",
        );
        assert(
            !inactive_clause | ((set_values[2 * j] == 0) & (set_values[2 * j + 1] == 0)),
            "malformed",
        );
        let lo_field = if active_clause { set_values[2 * j] } else { 0 };
        let hi_field = if active_clause { set_values[2 * j + 1] } else { 0 };
        clause_los[j] = lo_field as u64;
        clause_his[j] = hi_field as u64;
        assert(!active_clause | ((clause_los[j] as Field) == lo_field), "malformed");
        assert(!active_clause | ((clause_his[j] as Field) == hi_field), "malformed");
    }

    let mut eff_lo: u64 = clause_los[0];
    let mut eff_inc_lo: bool = inc_flags[0];
    let mut eff_hi: u64 = clause_his[0];
    let mut eff_inc_hi: bool = inc_flags[1];

    for j in 1..MAX_INTERVAL_CLAUSES {
        let active_clause = check_interval & (j < num_clauses);
        let c_lo = clause_los[j];
        let c_inc_lo = inc_flags[2 * j];
        let c_hi = clause_his[j];
        let c_inc_hi = inc_flags[2 * j + 1];

        if active_clause {
            if c_lo > eff_lo {
                eff_lo = c_lo;
                eff_inc_lo = c_inc_lo;
            } else if c_lo == eff_lo {
                eff_inc_lo = eff_inc_lo & c_inc_lo;
            }

            if c_hi < eff_hi {
                eff_hi = c_hi;
                eff_inc_hi = c_inc_hi;
            } else if c_hi == eff_hi {
                eff_inc_hi = eff_inc_hi & c_inc_hi;
            }
        }
    }

    assert(
        !check_interval | (eff_lo == lower_u64),
        "non-canonical interval bounds",
    );
    assert(
        !check_interval | (eff_hi == upper_u64),
        "non-canonical interval bounds",
    );
    let expected_packed =
        pack_canonical_interval_conjunction(eff_lo, eff_hi, eff_inc_lo, eff_inc_hi);
    assert(
        !check_interval | (public_value == expected_packed),
        "non-canonical interval bounds",
    );

    let lo_overflow = (!eff_inc_lo) & (eff_lo == U64_MAX);
    let hi_underflow = (!eff_inc_hi) & (eff_hi == 0);
    let min_valid: u64 = if eff_inc_lo {
        eff_lo
    } else if eff_lo < U64_MAX {
        eff_lo + 1
    } else {
        eff_lo
    };
    let max_valid: u64 = if eff_inc_hi {
        eff_hi
    } else if eff_hi > 0 {
        eff_hi - 1
    } else {
        0
    };
    let non_empty = (!lo_overflow) & (!hi_underflow) & (min_valid <= max_valid);
    assert(!check_interval | non_empty, "empty interval intersection");

    assert(
        !check_interval | ((attr_u64 >= min_valid) & (attr_u64 <= max_valid)),
        "interval bound unsatisfied",
    );
    for j in 0..MAX_INTERVAL_CLAUSES {
        let active_clause = check_interval & (j < num_clauses);
        let lo_ok = (attr_u64 > clause_los[j]) | (inc_flags[2 * j] & (attr_u64 == clause_los[j]));
        let hi_ok =
            (attr_u64 < clause_his[j]) | (inc_flags[2 * j + 1] & (attr_u64 == clause_his[j]));
        assert(!active_clause | (lo_ok & hi_ok), "interval bound unsatisfied");
    }
}

fn compute_predicate_commitment(
    predicates: [Predicate; MAX_PREDICATES],
    num_predicates: u32,
) -> Field {
    let mut current: Field = 0;
    for i in 0..MAX_PREDICATES {
        let p = predicates[i];
        let next = pedersen_hash([
            current,
            p.predicate_type,
            p.attr_index as Field,
            p.public_value,
        ]);
        if i < num_predicates {
            current = next;
        }
    }
    current
}

struct Predicate {
    predicate_type: Field,
    attr_index: u32,
    public_value: Field,
    set_values: [Field; MAX_SET_MEMBERS],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
}

fn main(
    schema_hash: pub Field,
    issuer_namespace: pub Field,
    schema_version: pub Field,
    credential_root: pub Field,
    nullifier: pub Field,
    video_hash_hi: pub Field,
    video_hash_lo: pub Field,
    verifier_digest: pub Field,
    circuit_version: pub Field,
    evidence_digest: pub Field,
    predicate_commitment: pub Field,
    num_attributes: u32,
    attr_values: [Field; MAX_ATTRIBUTES],
    attr_blindings: [Field; MAX_ATTRIBUTES],
    num_predicates: u32,
    predicates: [Predicate; MAX_PREDICATES],
) {
    for i in 0..MAX_PREDICATES {
        let is_active = i < num_predicates;
        assert_valid_predicate_type(predicates[i].predicate_type, is_active);
    }

    assert(
        circuit_version == CURRENT_CIRCUIT_VERSION as Field,
        "circuit version mismatch",
    );

    assert(num_attributes > 0, "malformed");
    assert(num_attributes <= MAX_ATTRIBUTES, "oversized");
    assert(num_predicates <= MAX_PREDICATES, "oversized");
    for i in 0..MAX_PREDICATES {
        let is_active = i < num_predicates;
        let valid_attr_index = predicates[i].attr_index < num_attributes;
        assert(!is_active | valid_attr_index, "malformed");

        let is_set = predicates[i].predicate_type == set_membership_predicate_type();
        let check_set = is_active & is_set;
        let set_len_gt_0 = predicates[i].set_len > 0;
        let set_len_valid = predicates[i].set_len <= MAX_SET_MEMBERS;
        assert(!check_set | set_len_gt_0, "malformed");
        assert(!check_set | set_len_valid, "oversized");

        let is_interval = predicates[i].predicate_type == interval_intersection_predicate_type();
        let check_interval = is_active & is_interval;
        let num_clauses = predicates[i].set_len & 255;
        assert(!check_interval | (num_clauses > 0), "malformed");
        assert(!check_interval | (num_clauses <= MAX_INTERVAL_CLAUSES), "oversized");
    }

    let mut commitments: [Field; MAX_ATTRIBUTES] = [0; MAX_ATTRIBUTES];
    for i in 0..MAX_ATTRIBUTES {
        commitments[i] = attr_commitment(attr_values[i], attr_blindings[i]);
    }

    let derived_root = compute_credential_root(commitments, num_attributes);
    assert(derived_root == credential_root, "malformed");

    for i in 0..MAX_PREDICATES {
        let pred = predicates[i];
        let is_active = i < num_predicates;
        let safe_attr_index = if pred.attr_index < MAX_ATTRIBUTES { pred.attr_index } else { 0 };
        verify_predicate(
            pred.predicate_type,
            attr_values[safe_attr_index],
            pred.public_value,
            pred.set_values,
            pred.set_len,
            pred.lower_bound,
            pred.upper_bound,
            is_active,
        );
    }

    let derived_pred_commitment = compute_predicate_commitment(predicates, num_predicates);
    assert(
        derived_pred_commitment == predicate_commitment,
        "predicate commitment mismatch",
    );

    let derived_nullifier = pedersen_hash([
        credential_root,
        video_hash_hi,
        video_hash_lo,
        evidence_digest,
    ]);
    assert(derived_nullifier == nullifier, "malformed");

    let _derived_verifier_digest = pedersen_hash([
        verifier_digest,
        schema_hash,
        circuit_version,
    ]);
    assert(verifier_digest != 0, "malformed");
}

fn make_predicate(
    predicate_type: Field,
    attr_index: u32,
    public_value: Field,
    set_values: [Field; 8],
    set_len: u32,
    lower_bound: Field,
    upper_bound: Field,
) -> Predicate {
    Predicate {
        predicate_type,
        attr_index,
        public_value,
        set_values,
        set_len,
        lower_bound,
        upper_bound,
    }
}

fn make_interval_predicate(
    attr_index: u32,
    set_values: [Field; 8],
    num_clauses: u32,
    clause_mask: u32,
    canonical_lo: u64,
    canonical_hi: u64,
    canonical_lo_inc: bool,
    canonical_hi_inc: bool,
) -> Predicate {
    let packed = pack_canonical_interval_conjunction(
        canonical_lo,
        canonical_hi,
        canonical_lo_inc,
        canonical_hi_inc,
    );
    Predicate {
        predicate_type: INTERVAL_INTERSECTION_PREDICATE_TYPE,
        attr_index,
        public_value: packed,
        set_values,
        set_len: num_clauses | (clause_mask << 8),
        lower_bound: canonical_lo as Field,
        upper_bound: canonical_hi as Field,
    }
}

fn default_attr_values() -> [Field; 16] {
    [18, 12345678, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn default_blindings() -> [Field; 16] {
    [111111, 222222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn default_padding_predicates() -> [Predicate; 8] {
    [make_predicate(0, 0, 0, [0; 8], 0, 0, 0); 8]
}

fn default_preds() -> [Predicate; 8] {
    let mut p = default_padding_predicates();
    p[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    p
}

fn run_test(
    schema_hash: Field,
    num_attributes: u32,
    attr_values: [Field; 16],
    attr_blindings: [Field; 16],
    num_predicates: u32,
    predicates: [Predicate; 8],
    _expected_fail: bool,
) {
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        commitments[i] = attr_commitment(attr_values[i], attr_blindings[i]);
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let predicate_commitment = compute_predicate_commitment(predicates, num_predicates);
    let verifier_digest = 42;

    main(
        schema_hash,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        verifier_digest,
        1,
        9999,
        predicate_commitment,
        num_attributes,
        attr_values,
        attr_blindings,
        num_predicates,
        predicates,
    );
}

#[test]
fn test_valid_equality_predicate() {
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        default_preds(),
        false,
    );
}

#[test]
fn test_valid_range_predicate() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_set_membership_predicate() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [12345678, 87654321, 11111111, 0, 0, 0, 0, 0], 3, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_multiple_predicates() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[1] = make_predicate(1, 1, 0, [12345678, 87654321, 11111111, 0, 0, 0, 0, 0], 3, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        2,
        preds,
        false,
    );
}

#[test]
fn test_range_lower_bound_edge() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_range_upper_bound_edge() {
    let mut attr_vals = default_attr_values();
    attr_vals[0] = 99;
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_set_membership_single_element() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [12345678, 0, 0, 0, 0, 0, 0, 0], 1, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

// ============================================================
// Interval Intersection Predicates (predicate_type == 3)
// ============================================================

#[test]
fn test_valid_interval_intersection_half_open_boundaries() {
    // [10, 30] (bits 0b11 = 3) intersect (18, 25] (bits 0b10 = 2, shifted << 2 => 8)
    // => canonical (18, 25], mask = 3 | 8 = 11.
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 30, 18, 25, 0, 0, 0, 0], 2, 11, 18, 25, false, true);

    // Lower interior boundary: 19 satisfies (18, 25]
    let mut attrs_lo = default_attr_values();
    attrs_lo[0] = 19;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attrs_lo,
        default_blindings(),
        1,
        preds,
        false,
    );

    // Exact inclusive upper boundary: 25 satisfies (18, 25]
    let mut attrs_hi = default_attr_values();
    attrs_hi[0] = 25;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attrs_hi,
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_interval_intersection_closed_singleton() {
    // [10, 18] (0b11 = 3) intersect [18, 30] (0b11 << 2 = 12) => [18, 18], mask = 15
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 18, 18, 30, 0, 0, 0, 0], 2, 15, 18, 18, true, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        false,
    );
}

#[test]
fn test_valid_interval_intersection_order_invariance_and_hidden_value() {
    // Order A: [10, 40] (3) & (20, 60) (0) => (20, 40], mask = 3
    let mut preds_a = default_padding_predicates();
    preds_a[0] = make_interval_predicate(0, [10, 40, 20, 60, 0, 0, 0, 0], 2, 3, 20, 40, false, true);

    // Order B: (20, 60) (0) & [10, 40] (3 << 2 = 12) => (20, 40], mask = 12
    let mut preds_b = default_padding_predicates();
    preds_b[0] = make_interval_predicate(0, [20, 60, 10, 40, 0, 0, 0, 0], 2, 12, 20, 40, false, true);

    // Public predicate commitments are identical across clause permutations and certified values!
    let comm_a = compute_predicate_commitment(preds_a, 1);
    let comm_b = compute_predicate_commitment(preds_b, 1);
    assert(comm_a == comm_b, "canonical conjunction commitment must be order-independent");

    let mut attrs_first = default_attr_values();
    attrs_first[0] = 21;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attrs_first,
        default_blindings(),
        1,
        preds_a,
        false,
    );

    let mut attrs_second = default_attr_values();
    attrs_second[0] = 40;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attrs_second,
        default_blindings(),
        1,
        preds_b,
        false,
    );
}

#[test(should_fail_with = "interval bound unsatisfied")]
fn test_rejects_interval_excluded_lower_boundary() {
    // [10, 30] & (18, 25] => (18, 25]; default attr_values[0] = 18 is excluded.
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 30, 18, 25, 0, 0, 0, 0], 2, 11, 18, 25, false, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "interval bound unsatisfied")]
fn test_rejects_interval_excluded_upper_boundary() {
    // [10, 25) (0b01 = 1) & [18, 30] (0b11 << 2 = 12) => [18, 25), mask = 13; 25 is excluded.
    let mut attr_vals = default_attr_values();
    attr_vals[0] = 25;
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 25, 18, 30, 0, 0, 0, 0], 2, 13, 18, 25, true, false);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_rejects_field_overflow_in_interval_attribute() {
    // 2^64 + 20 would wrap to 20 under raw `as u64`; non-truncation check rejects it.
    let mut attr_vals = default_attr_values();
    attr_vals[0] = TWO_POW_64 + 20;
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 30, 18, 25, 0, 0, 0, 0], 2, 11, 18, 25, false, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "empty interval intersection")]
fn test_rejects_empty_touching_exclusive_interval() {
    // [10, 18) (0b01 = 1) & [18, 25] (0b11 << 2 = 12) => [18, 18), mask = 13 (empty!)
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 18, 18, 25, 0, 0, 0, 0], 2, 13, 18, 18, true, false);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "empty interval intersection")]
fn test_rejects_empty_adjacent_open_integer_interval() {
    // (18, 25] (0b10 = 2) & [10, 19) (0b01 << 2 = 4) => (18, 19), mask = 6 (no u64 integer in (18, 19)!)
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [18, 25, 10, 19, 0, 0, 0, 0], 2, 6, 18, 19, false, false);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "empty interval intersection")]
fn test_rejects_empty_disjoint_intervals() {
    // [10, 15] (3) & [20, 25] (12) => [20, 15], mask = 15 (empty!)
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 15, 20, 25, 0, 0, 0, 0], 2, 15, 20, 15, true, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "non-canonical interval bounds")]
fn test_rejects_non_canonical_interval_bounds() {
    // Clauses reduce to (18, 25] (lower exclusive), but prover claims [18, 25] (lower inclusive).
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 30, 18, 25, 0, 0, 0, 0], 2, 11, 18, 25, true, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "oversized")]
fn test_rejects_oversized_interval_clause_count() {
    let mut preds = default_padding_predicates();
    preds[0] = make_interval_predicate(0, [10, 30, 12, 28, 14, 26, 16, 24], 5, 255, 16, 24, true, true);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_equality_wrong_value() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 0, 21, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_range_below_lower() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 21, 99);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_range_above_upper() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(2, 0, 0, [0; 8], 0, 18, 17);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_set_membership_not_in_set() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [87654321, 11111111, 0, 0, 0, 0, 0, 0], 2, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_set_membership_empty_set() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(1, 1, 0, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_wrong_credential_root() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);
    let wrong_root: Field = 123456789;
    let nullifier = pedersen_hash([wrong_root, 1234, 5678, 9999]);

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        wrong_root,
        nullifier,
        1234,
        5678,
        42,
        1,
        9999,
        predicate_commitment,
        2,
        attr_vals,
        blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "malformed")]
fn test_wrong_attribute_value() {
    let mut attr_vals = default_attr_values();
    attr_vals[0] = 19;
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        attr_vals,
        default_blindings(),
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_wrong_blinding() {
    let attr_vals = default_attr_values();
    let orig_blindings = default_blindings();
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        commitments[i] = attr_commitment(attr_vals[i], orig_blindings[i]);
    }
    let credential_root = compute_credential_root(commitments, 2);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);

    let mut wrong_blindings = orig_blindings;
    wrong_blindings[0] = 999999;

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        42,
        1,
        9999,
        predicate_commitment,
        2,
        attr_vals,
        wrong_blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "circuit version mismatch")]
fn test_circuit_version_downgrade() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        42,
        0,
        9999,
        predicate_commitment,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "malformed")]
fn test_zero_attributes() {
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0,
        default_attr_values(),
        default_blindings(),
        1,
        default_preds(),
        true,
    );
}

#[test(should_fail_with = "oversized")]
fn test_too_many_predicates() {
    let mut preds = default_preds();
    preds[0] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[1] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[2] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[3] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[4] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[5] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[6] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    preds[7] = make_predicate(0, 0, 18, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        9,
        preds,
        true,
    );
}

#[test(should_fail_with = "unsupported predicate type")]
fn test_unsupported_predicate_type() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(42, 0, 0, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "malformed")]
fn test_predicate_out_of_range_attr_index() {
    let mut preds = default_padding_predicates();
    preds[0] = make_predicate(0, 99, 18, [0; 8], 0, 0, 0);
    run_test(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        2,
        default_attr_values(),
        default_blindings(),
        1,
        preds,
        true,
    );
}

#[test(should_fail_with = "predicate commitment mismatch")]
fn test_predicate_commitment_mismatch() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        42,
        1,
        9999,
        0,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}

#[test(should_fail_with = "malformed")]
fn test_zero_verifier_digest() {
    let attr_vals = default_attr_values();
    let blindings = default_blindings();
    let num_attributes: u32 = 2;
    let mut commitments: [Field; 16] = [0; 16];
    for i in 0..16 {
        commitments[i] = attr_commitment(attr_vals[i], blindings[i]);
    }
    let credential_root = compute_credential_root(commitments, num_attributes);
    let nullifier = pedersen_hash([credential_root, 1234, 5678, 9999]);
    let preds = default_preds();
    let predicate_commitment = compute_predicate_commitment(preds, 1);

    main(
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        1,
        credential_root,
        nullifier,
        1234,
        5678,
        0,
        1,
        9999,
        predicate_commitment,
        num_attributes,
        attr_vals,
        blindings,
        1,
        preds,
    );
}
