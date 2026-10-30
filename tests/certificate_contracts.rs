//! Certificate observers retain their independent diagnostic and handler loans.
//!
//! ```compile_fail
//! use dope_quic::{conn::id, runtime::mux::handler::hook::wire::cert::Event};
//! fn escape<'wire>(event: Event<'_, 'wire, (), 0, id::Static>) -> &'static rustls::Error {
//!     event.into_parts().3
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::{conn::id, runtime::mux::handler::hook::wire::cert::Event};
//! fn escape(event: Event<'_, '_, (), 0, id::Static>) -> std::pin::Pin<&'static mut ()> {
//!     event.into_parts().0
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::{conn::id, runtime::mux::handler::hook::wire::cert::Event};
//! fn reroute<'a, 'b>(event: Event<'a, 'b, (), 0, id::Static>) -> Event<'a, 'b, (), 1, id::Static> {
//!     event
//! }
//! ```

//! ```
//! use dope_quic::{conn::id, runtime::mux::handler::hook::wire::cert::Event};
//! use std::{net::SocketAddr, pin::Pin};
//! fn preserve<'scope, 'wire, H>(event: Event<'scope, 'wire, H, 0, id::Static>)
//!     -> (Pin<&'scope mut H>, id::Handle, SocketAddr, &'wire rustls::Error)
//! {
//!     event.into_parts()
//! }
//! ```

#[test]
fn retains_observer_loans() {
    use std::env;

    use dope_test::checks::Suite;
    let suite = Suite::new(
        env!("CARGO_MANIFEST_DIR"),
        file!(),
        &["dope-quic", "rustls"],
    );
    let exe = env::current_exe().expect("test executable");
    let status = suite
        .try_build(&exe, env!("CARGO_PKG_NAME"))
        .expect("build command")
        .status()
        .expect("build original library");
    assert!(status.success(), "build original library: {status}");
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(
        status.success(),
        "certificate observer lifetime contracts: {status}"
    );
}
