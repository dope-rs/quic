//! Client ownership and lifetime contracts.
//!
//! ```compile_fail
//! use dope_quic::client::{auth, Backoff, ConfigSource, Dialer, protocol::Protocol};
//!
//! fn erase_pool_lifetime<'pool, 'd, 'tls, const ID: u8, P, B, C>(
//!     dialer: Dialer<'pool, 'd, ID, P, B, auth::Pooled<'tls>, C>,
//! ) -> Dialer<'pool, 'd, ID, P, B, auth::Pooled<'static>, C>
//! where
//!     P: Protocol<'d>,
//!     B: Backoff,
//!     C: ConfigSource,
//! {
//!     dialer
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::{Backoff, Dialer, protocol::Protocol};
//!
//! fn escape<'pool, 'd, const ID: u8, P: Protocol<'d>, B: Backoff>(
//!     dialer: Dialer<'pool, 'd, ID, P, B>,
//! ) -> Dialer<'static, 'd, ID, P, B> {
//!     dialer
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::SlotScope;
//!
//! fn escape(scope: SlotScope<'_>) -> SlotScope<'static> {
//!     scope
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::AttemptScope;
//!
//! fn escape(scope: AttemptScope<'_, '_>) -> AttemptScope<'static, 'static> {
//!     scope
//! }
//!
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::AttemptScope;
//! fn erase_driver_time<'scope, 'd>(
//!     scope: AttemptScope<'scope, 'd>,
//! ) -> dope::core::driver::schedule::clock::Moment<'static> {
//!     scope.started_at()
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::RetryScope;
//!
//! fn escape(scope: RetryScope<'_>) -> RetryScope<'static> {
//!     scope
//! }
//! ```
//!
//! ```
//! use dope_quic::client::{Backoff, RetryScope};
//! use std::cell::Cell;
//! use std::time::Duration;
//!
//! struct Borrowed<'owner>(&'owner Cell<u32>);
//!
//! impl Backoff for Borrowed<'_> {
//!     fn retry_after<'scope>(&'scope self, retry: RetryScope<'scope>) -> Duration {
//!         self.0.set(retry.failures());
//!         Duration::ZERO
//!     }
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::client::{
//!     AttemptScope, Backoff, ConfigSource, Dialer, RetryScope, auth, protocol,
//! };
//! use dope_quic::conn::life::options::Options;
//! use std::time::Duration;
//!
//! struct BorrowedBackoff<'owner>(&'owner ());
//! struct BorrowedConfig<'owner>(&'owner ());
//!
//! impl Backoff for BorrowedBackoff<'_> {
//!     fn retry_after<'scope>(&'scope self, _: RetryScope<'scope>) -> Duration {
//!         Duration::ZERO
//!     }
//! }
//!
//! impl ConfigSource for BorrowedConfig<'_> {
//!     fn config<'scope, 'd>(
//!         &'scope mut self,
//!         _: AttemptScope<'scope, 'd>,
//!     ) -> Option<Options> {
//!         None
//!     }
//! }
//!
//! fn erase<'pool, 'd, 'owner, const ID: u8, P>(
//!     dialer: Dialer<
//!         'pool,
//!         'd,
//!         ID,
//!         P,
//!         BorrowedBackoff<'owner>,
//!         auth::Owned,
//!         BorrowedConfig<'owner>,
//!     >,
//! ) -> Dialer<
//!     'pool,
//!     'd,
//!     ID,
//!     P,
//!     BorrowedBackoff<'static>,
//!     auth::Owned,
//!     BorrowedConfig<'static>,
//! >
//! where
//!     P: protocol::Protocol<'d>,
//! {
//!     dialer
//! }
//! ```
//!
//! ```
//! use dope_quic::client::{AttemptScope, ConfigSource};
//! use dope_quic::conn::life::options::Options;
//! use std::cell::Cell;
//!
//! struct Borrowed<'owner>(&'owner Cell<u32>);
//!
//! impl ConfigSource for Borrowed<'_> {
//!     fn config<'scope, 'd>(
//!         &'scope mut self,
//!         attempt: AttemptScope<'scope, 'd>,
//!     ) -> Option<Options> {
//!         self.0.set(attempt.attempt());
//!         None
//!     }
//! }
//! ```
//!

//! ```
//! use dope_quic::client::{auth, Backoff, ConfigSource, Dialer, protocol::Protocol};
//! use dope_quic::client::{AttemptScope, RetryScope, SlotScope};
//! use dope::core::driver::schedule::clock::Moment;
//! fn pooled<'pool, 'd, 'tls, const ID: u8, P, B, C>(
//!     dialer: Dialer<'pool, 'd, ID, P, B, auth::Pooled<'tls>, C>,
//! ) -> Dialer<'pool, 'd, ID, P, B, auth::Pooled<'tls>, C>
//! where P: Protocol<'d>, B: Backoff, C: ConfigSource {
//!     dialer
//! }
//! fn packets<'pool, 'd, const ID: u8, P: Protocol<'d>, B: Backoff>(
//!     dialer: Dialer<'pool, 'd, ID, P, B>,
//! ) -> Dialer<'pool, 'd, ID, P, B> { dialer }
//! fn slot<'scope>(scope: SlotScope<'scope>) -> SlotScope<'scope> { scope }
//! fn attempt<'scope, 'd>(scope: AttemptScope<'scope, 'd>) -> AttemptScope<'scope, 'd> { scope }
//! fn moment<'d>(scope: AttemptScope<'_, 'd>) -> Moment<'d> { scope.started_at() }
//! fn retry<'scope>(scope: RetryScope<'scope>) -> RetryScope<'scope> { scope }
//! ```

//! ```
//! use dope_quic::client::{
//!     AttemptScope, Backoff, ConfigSource, Dialer, RetryScope, auth, protocol,
//! };
//! use dope_quic::conn::life::options::Options;
//! use std::time::Duration;
//!
//! struct BorrowedBackoff<'owner>(&'owner ());
//! struct BorrowedConfig<'owner>(&'owner ());
//!
//! impl Backoff for BorrowedBackoff<'_> {
//!     fn retry_after<'scope>(&'scope self, _: RetryScope<'scope>) -> Duration {
//!         Duration::ZERO
//!     }
//! }
//!
//! impl ConfigSource for BorrowedConfig<'_> {
//!     fn config<'scope, 'd>(
//!         &'scope mut self,
//!         _: AttemptScope<'scope, 'd>,
//!     ) -> Option<Options> {
//!         None
//!     }
//! }
//!
//! fn erase<'pool, 'd, 'owner, const ID: u8, P>(
//!     dialer: Dialer<
//!         'pool,
//!         'd,
//!         ID,
//!         P,
//!         BorrowedBackoff<'owner>,
//!         auth::Owned,
//!         BorrowedConfig<'owner>,
//!     >,
//! ) -> Dialer<
//!     'pool,
//!     'd,
//!     ID,
//!     P,
//!     BorrowedBackoff<'owner>,
//!     auth::Owned,
//!     BorrowedConfig<'owner>,
//! >
//! where
//!     P: protocol::Protocol<'d>,
//! {
//!     dialer
//! }
//! ```

#[test]
fn retains_client_proofs() {
    use std::env;

    use dope_test::checks::Suite;
    let suite = Suite::new(
        env!("CARGO_MANIFEST_DIR"),
        file!(),
        &["dope-quic", "dope", "o3"],
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
    assert!(status.success(), "client ownership contracts: {status}");
}
