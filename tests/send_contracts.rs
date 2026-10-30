//! Admission and discard receipts retain the original write operation at the commit boundary.
//!
//! ```compile_fail,E0308
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn mismatch<O: buffer::raw::Segment, W, V, C: admit::Commit<O, V>>(
//!     commit: C, receipt: admit::Admission<'_, O, W>,
//! ) -> C::Retained {
//!     commit.retained(receipt)
//! }
//! ```
//!
//! ```compile_fail,E0308
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn mismatch<O: buffer::raw::Segment, W, V, C: admit::Commit<O, V>>(
//!     commit: C, receipt: admit::Discard<W>,
//! ) -> C::Discarded {
//!     commit.discarded(receipt)
//! }
//! ```
//!
//! ```compile_fail,E0308
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn replace<O: buffer::raw::Segment, W, V, C: admit::Commit<O, W>, E>(
//!     commit: C, owner: V,
//! ) -> admit::Outcome<O, C, E, W> {
//!     admit::Outcome::Blocked { owner, commit }
//! }
//! ```

//! ```
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn matching<O: buffer::raw::Segment, W, C: admit::Commit<O, W>>(
//!     commit: C, receipt: admit::Admission<'_, O, W>,
//! ) -> C::Retained {
//!     commit.retained(receipt)
//! }
//! ```
//!
//! ```
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn matching<O: buffer::raw::Segment, W, C: admit::Commit<O, W>>(
//!     commit: C, receipt: admit::Discard<W>,
//! ) -> C::Discarded {
//!     commit.discarded(receipt)
//! }
//! ```
//!
//! ```
//! use dope_quic::stream::send::admit;
//! use o3::buffer;
//! fn preserve<O: buffer::raw::Segment, W, C: admit::Commit<O, W>, E>(
//!     commit: C, owner: W,
//! ) -> admit::Outcome<O, C, E, W> {
//!     admit::Outcome::Blocked { owner, commit }
//! }
//! ```

#[test]
fn retains_write_identity() {
    use std::env;

    use dope_test::checks::Suite;
    let suite = Suite::new(env!("CARGO_MANIFEST_DIR"), file!(), &["dope-quic", "o3"]);
    let exe = env::current_exe().expect("test executable");
    let status = suite
        .try_build(&exe, env!("CARGO_PKG_NAME"))
        .expect("build command")
        .status()
        .expect("build original library");
    assert!(status.success(), "build original library: {status}");
    assert_eq!(
        suite
            .try_errors(&exe, include_str!("send_contracts.rs"))
            .expect("exact compiler errors"),
        3
    );
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(
        status.success(),
        "send admission and discard operation identity: {status}"
    );
}
