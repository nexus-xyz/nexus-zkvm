#[test]
fn test() {
    let t = trybuild::TestCases::new();

    t.compile_fail("build-tests/00-fn-ident-mismatch.rs");
    t.pass("build-tests/01-basic.rs");
    t.compile_fail("build-tests/02-invalid-fn-sig.rs");
    t.compile_fail("build-tests/03-invalid-fn-ptr-type.rs");
}
