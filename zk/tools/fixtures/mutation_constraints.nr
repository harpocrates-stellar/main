fn constrain_value(x: Field) {
    assert(x != 100, "oversized");
}

fn main(x: Field) {
    // assert(false, "not executable");
    /* A nested comment: /* assert_eq(1, 2); */ still a comment. */
    let label = "assert(false); and escaped \"quotes\"";
    constrain_value(x);
    assert(
        x != 0,
        "malformed",
    );
    assert_eq(x, 7, "wrong value");
}

#[test]
fn positive() {
    main(7);
    assert(1 == 1);
}

#[test(should_fail_with = "malformed")]
fn negative() {
    main(0);
    assert(false, "do not mutate the test oracle");
}

#[test(should_fail_with = "oversized")]
fn helper_negative() {
    main(100);
}

#[test(should_fail_with = "wrong value")]
fn equality_negative() {
    main(8);
}
