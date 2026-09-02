//! `kumo_wrap::set_soft_wrap_enabled` flips process-wide global state,
//! so this lives in its own integration test binary (a separate
//! process from `cargo test`'s unit tests) to avoid racing the many
//! unit tests in `mailparsing::header` that assert on default wrap
//! behavior.

use mailparsing::Header;

/// Restores the global soft-wrap toggle to its default (enabled) state
/// when dropped, so a panic mid-test can't leak state into any test
/// added later to this binary.
struct SoftWrapGuard;

impl Drop for SoftWrapGuard {
    fn drop(&mut self) {
        kumo_wrap::set_soft_wrap_enabled(true);
    }
}

#[test]
fn unstructured_header_respects_soft_wrap_toggle() {
    let _guard = SoftWrapGuard;
    let long_value = "hello there, this is a \
        longer header than the standard width and so it should \
        get wrapped in the produced value";

    kumo_wrap::set_soft_wrap_enabled(false);
    let header = Header::new_unstructured("Subject", long_value);
    assert_eq!(header.get_raw_value_string().unwrap(), long_value);

    kumo_wrap::set_soft_wrap_enabled(true);
    let header = Header::new_unstructured("Subject", long_value);
    assert!(
        header.get_raw_value_string().unwrap().contains("\r\n\t"),
        "expected soft wrap to resume once re-enabled"
    );
}
