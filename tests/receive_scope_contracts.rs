//! Receive ownership and lifetime contracts.
//!
//! ```compile_fail,E0624
//! use dope_quic::{conn, runtime::mux::handler::Slot};
//! use o3::buffer::storage::Shared;
//!
//! fn bypass(slot: &mut Slot<'_, (), 0, Vec<u8>, Shared>, work: &mut conn::Workspace) {
//!     slot.transport().input(work);
//! }
//! ```
//!
//! ```compile_fail,E0603
//! use dope_quic::conn::life::Token;
//!
//! Token {
//!     storage: vec![1].into_boxed_slice(),
//! };
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::life::Connection;
//! fn escape<'a, 'p>(connection: &'a mut Connection<'p>) -> impl Sized + 'a {
//!     connection.with_scope(|scope| scope)
//! }
//! ```
//!
//! ```compile_fail,E0596
//! use dope_quic::conn::{self, life};
//! fn detach(pooled: &mut life::Connection<'_>, owned: &mut conn::Connection) {
//!     std::mem::swap(&mut **pooled, owned);
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::Connection;
//! fn cross(left: &mut Connection, right: &mut Connection) {
//!     left.with_scope(|mut left| right.with_scope(|mut right| {
//!         let stream = left.streams().send().open_bidi().expect("fixture stream");
//!         assert!(right.streams().send().send(stream.send(), b"wrong owner").is_ok());
//!     }));
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::life::status;
//!
//! fn cannot_export_raw_deadline(view: status::Inspection<'_>) {
//!     view.recovery().next_timer();
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::life::Connection;
//!
//! fn erase_pool_lifetime(connection: Connection<'_>) -> Connection<'static> {
//!     connection
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::{Connection, Workspace};
//!
//! fn leak_input(connection: &mut Connection) -> impl Sized + '_ {
//!     let mut workspace = Workspace::try_new().expect("receive workspace allocation");
//!     connection.with_scope(|mut scope| scope.input(&mut workspace))
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::Connection;
//!
//! fn leak_scope(connection: &mut Connection) -> impl Sized + '_ {
//!     connection.with_scope(|scope| scope)
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::stream::recv::{Receive, hold::Held};
//!
//! fn cross<'first, 'second>(
//!     held: Held<'first, Vec<u8>>,
//!     receive: &mut Receive<'_, 'second, 0>,
//! ) {
//!     held.release(receive);
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::stream::recv::hold::Detached;
//! use dope_quic::stream::RecvBuffer;
//!
//! fn erase<'driver>(held: Detached<RecvBuffer<'driver>>)
//!     -> Detached<RecvBuffer<'static>>
//! {
//!     held
//! }
//! ```
//!
//! ```compile_fail,E0521
//! use dope_quic::stream::RecvBuffer;
//! use o3::buffer::bytes::scope;
//! fn swap(first: &mut RecvBuffer<'_>, second: &mut RecvBuffer<'_>) {
//!     scope::Owner::with(first, |owner| {
//!         if let Ok((_, range)) = owner.view().try_rsplit::<1>() {
//!             scope::Owner::with(second, |owner| owner.project(range));
//!         }
//!     });
//! }
//! ```
//!

//! ```
//! use dope_quic::{conn, stream::RecvBuffer};
//! use conn::life;
//! use conn::stream::recv::{Receive, hold::{Held, Detached}};
//! use o3::buffer::bytes::scope;
//! use std::time::Instant;
//! fn pooled<'pool>(connection: life::Connection<'pool>) -> life::Connection<'pool> {
//!     connection
//! }
//! fn scoped(
//!     connection: &mut life::Connection<'_>,
//!     work: &mut conn::Workspace,
//!     wire: &mut [u8],
//!     now: Instant,
//! ) {
//!     connection.with_scope(|mut scope| {
//!         scope.input(work).recv_packet(wire, now, |_| {}).expect("receive packet");
//!         scope.output().send(now).1.expect("send packets");
//!     });
//! }
//! fn same(connection: &mut conn::Connection) {
//!     connection.with_scope(|mut owner| {
//!         let stream = owner.streams().send().open_bidi().expect("fixture stream");
//!         assert!(owner.streams().send().send(stream.send(), b"same owner").is_ok());
//!     });
//! }
//! fn inspect(view: life::status::Inspection<'_>) -> u64 { view.recovery().window() }
//! fn input(connection: &mut conn::Connection) {
//!     let mut workspace = conn::Workspace::try_new().expect("receive workspace allocation");
//!     connection.with_scope(|mut scope| { let _ = scope.input(&mut workspace); });
//! }
//! fn release<'conn>(held: Held<'conn, Vec<u8>>, receive: &mut Receive<'_, 'conn, 0>) -> Vec<u8> {
//!     held.release(receive)
//! }
//! fn detached<'driver>(held: Detached<RecvBuffer<'driver>>) -> Detached<RecvBuffer<'driver>> { held }
//! fn project(buffer: &mut RecvBuffer<'_>) {
//!     scope::Owner::with(buffer, |owner| {
//!         if let Ok((_, range)) = owner.view().try_rsplit::<1>() {
//!             owner.project(range);
//!         }
//!     });
//! }
//! ```

#[test]
fn retains_receive_proofs() {
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
    assert_eq!(
        suite
            .try_errors(&exe, include_str!("receive_scope_contracts.rs"))
            .expect("exact compiler errors"),
        4
    );
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(status.success(), "receive ownership contracts: {status}");
}
