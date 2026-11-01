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

//! Packet ownership and lifetime contracts.
//!
//! ```compile_fail
//! use dope_quic::wire::packet::long::Parsed;
//! fn parse<P: AsRef<[u8]>>(owner: P) {
//!     let _ = Parsed::parse(owner);
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::{security::qkdf::Initial, wire::packet::long::Parsed};
//! fn decrypt<P: o3::buffer::raw::Source + AsMut<[u8]>>(owner: P) {
//!     let key = Initial::try_new(&[]).unwrap().try_client().unwrap();
//!     let Parsed::Initial(packet) = Parsed::parse(owner).unwrap() else { return; };
//!     let _ = packet.decrypt(&key, 0);
//! }
//! ```
//!
//! ```
//! use dope_quic::{security::qkdf::Initial, wire::packet::long::Parsed};
//! fn parse<P: o3::buffer::raw::Source>(owner: P) {
//!     let _ = Parsed::parse(owner);
//! }
//! fn decrypt<P: o3::buffer::raw::Mutable>(owner: P) {
//!     let key = Initial::try_new(&[]).unwrap().try_client().unwrap();
//!     let Parsed::Initial(packet) = Parsed::parse(owner).unwrap() else { return; };
//!     let _ = packet.decrypt(&key, 0);
//! }
//! ```
//!
//! ```compile_fail,E0308
//! use dope_quic::errors::Code;
//!
//! // Raw integers cannot enter stream state or a control journal as if they
//! // had already been checked.
//! let _: Code = u64::MAX;
//! ```
//!
//! ```compile_fail
//! use dope_quic::proto::datagram::batch::Pending;
//! fn erase<'pool>(batch: Pending<'pool, 1>) -> Pending<'static, 1> { batch }
//! ```
//!
//! ```compile_fail
//! use dope_quic::proto::datagram::{Arena, Error, Packet};
//!
//! fn escape(arena: &Arena) -> Result<Packet<'static>, Error> {
//!     arena.try_acquire(1)
//! }
//! ```
//!
//! ```compile_fail,E0515
//! use dope_quic::{proto::param, wire::packet};
//! use packet::cid;
//!
//! fn escape() -> param::Client<'static> {
//!     let params = param::Set::default();
//!     let cid = cid::Id::try_from([1_u8]).unwrap();
//!     params.bind_client(&cid)
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use dope_quic::proto::param;
//!
//! param::Set { ..param::Set::default() };
//! ```
//!
//! ```compile_fail,E0308
//! use dope_quic::runtime::embedded::link::Link;
//!
//! fn reverse(link: Link<'static, 9, 7, 8>) -> Link<'static, 9, 8, 7> {
//!     link
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::conn::id;
//! use dope_quic::proto::datagram::Sealed;
//! use dope_quic::runtime::{endpoint::{self, Endpoint}, mux::handler};
//! use o3::buffer::resident;
//!
//! fn escape<'d, 'pool, H>(
//!     endpoint: Endpoint<'d, 0, H, Vec<u8>, endpoint::Idle,
//!         endpoint::owner::Owned, Sealed<'pool>>,
//! ) -> Endpoint<'d, 0, H, Vec<u8>, endpoint::Idle,
//!     endpoint::owner::Owned, Sealed<'static>>
//! where
//!     H: handler::Handler<0, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
//! {
//!     endpoint
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::runtime::mux::handler::Close;
//! fn escape(scope: Close<'_>) -> Close<'static> { scope }
//! ```
//!
//! ```compile_fail
//! use dope_quic::runtime::mux::handler::net::Ingress;
//!
//! fn erase_driver(ingress: Ingress<'_>) -> Ingress<'static> {
//!     ingress
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::runtime::mux::handler::net::Settlement;
//!
//! fn leak(settlement: Settlement<'_>) -> &'static [u8] {
//!     settlement.payload()
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::runtime::mux::handler::net::Settlement;
//!
//! use dope_quic::conn::id::Driver;
//!
//! fn erase_driver<'owner, 'd>(
//!     settlement: Settlement<'owner, Driver<'d>>,
//! ) -> Settlement<'owner, Driver<'static>> {
//!     settlement
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::runtime::mux::{auth, handler, router::observed::Observed};
//! use o3::buffer::storage;
//! fn close<H: handler::Handler<0, Vec<u8>, storage::Shared>>(
//!     mut turn: Observed<'_, '_, auth::Owned, H, 0>,
//! ) {
//!     turn.close_all();
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::wire::frame::{Frame, View, ack::ranges::Set};
//!
//! fn escape_packet_storage() -> Set<'static> {
//!     let wire = [0x02, 0, 0, 0, 0];
//!     let (frame, _) = Frame::decode_ref(&wire).unwrap();
//!     let View::Ack { additional_ranges, .. } = frame.view() else {
//!         unreachable!("ack")
//!     };
//!     additional_ranges.clone()
//! }
//! ```
//!
//! ```compile_fail
//! use dope_quic::wire::{frame::decode::Notice, packet::cid};
//! let id = cid::Ref::new(&[]).expect("bounded but empty");
//! let invalid = Notice { id, token: [0; 16] };
//! ```
//!
//! ```compile_fail
//! use dope_quic::wire::frame::{Frame, View};
//! let id = {
//!     let mut wire = [0; 21];
//!     wire[0] = 0x18;
//!     wire[3] = 1;
//!     let (frame, _) = Frame::decode_ref(&wire).expect("valid announcement");
//!     match frame.view() {
//!         View::NewConnectionId { notice, .. } => Some(notice.id().into_slice()),
//!         _ => None,
//!     }.expect("CID notice")
//! };
//! assert_eq!(id.len(), 1);
//! ```
//!
//! ```compile_fail
//! use dope_quic::wire::frame::Frame;
//!
//! // Variants are deliberately not public constructors: this cannot forge a
//! // frame that bypasses semantic validation.
//! Frame::NewToken { token: Vec::new() };
//! ```
//!

//! ```
//! use dope_quic::{errors::Code, proto::{datagram, param}, wire::{frame::{Frame, View}, packet::cid}};
//! use dope_quic::runtime::{embedded::link::Link, mux::{auth, handler, router::observed::Observed}};
//! use dope_quic::conn::id;
//! use o3::buffer::{storage, resident};
//! use dope_quic::runtime::endpoint::{self, Endpoint};
//! fn endpoint<'d, 'pool, H>(
//!     endpoint: Endpoint<'d, 0, H, Vec<u8>, endpoint::Idle,
//!         endpoint::owner::Owned, datagram::Sealed<'pool>>,
//! ) -> Endpoint<'d, 0, H, Vec<u8>, endpoint::Idle,
//!     endpoint::owner::Owned, datagram::Sealed<'pool>>
//! where H: handler::Handler<0, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> { endpoint }
//! fn packet(arena: &datagram::Arena) -> Result<datagram::Packet<'_>, datagram::Error> {
//!     arena.try_acquire(1)
//! }
//! fn batch<'pool>(batch: datagram::batch::Pending<'pool, 1>) -> datagram::batch::Pending<'pool, 1> {
//!     batch
//! }
//! fn direction(link: Link<'static, 9, 7, 8>) -> Link<'static, 9, 7, 8> { link }
//! fn close<'scope>(scope: handler::Close<'scope>) -> handler::Close<'scope> { scope }
//! fn ingress<'d>(value: handler::net::Ingress<'d>) -> handler::net::Ingress<'d> { value }
//! fn payload<'owner>(value: handler::net::Settlement<'owner>) -> &'owner [u8] { value.payload() }
//! fn settlement<'owner, 'd>(value: handler::net::Settlement<'owner, id::Driver<'d>>)
//!     -> handler::net::Settlement<'owner, id::Driver<'d>> { value }
//! fn seal<H: handler::Handler<0, Vec<u8>, storage::Shared>>(
//!     turn: Observed<'_, '_, auth::Owned, H, 0>,
//! ) { turn.seal().close_all(); }
//! assert!(Code::new(u64::MAX).is_none());
//! let params = param::Set::default();
//! let cid = cid::Id::try_from([1_u8]).expect("connection id");
//! let _ = params.bind_client(&cid);
//! let wire = [0x02, 0, 0, 0, 0];
//! let (frame, _) = Frame::decode_ref(&wire).expect("ACK frame");
//! let View::Ack { additional_ranges, .. } = frame.view() else { unreachable!("ack") };
//! let _: dope_quic::wire::frame::ack::ranges::Set<'_> = additional_ranges.clone();
//! let mut wire = [0; 21];
//! wire[0] = 0x18;
//! wire[3] = 1;
//! let (frame, _) = Frame::decode_ref(&wire).expect("CID frame");
//! let View::NewConnectionId { notice, .. } = frame.view() else { unreachable!("cid") };
//! assert_eq!(notice.id().into_slice().len(), 1);
//! ```

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

#[cfg(test)]
use dope_test::checks::{Error, Suite};

#[test]
fn retains_ownership_proofs() -> Result<(), Error> {
    let exe = std::env::current_exe()?;
    let suite = Suite::new(
        env!("CARGO_MANIFEST_DIR"),
        file!(),
        &["dope-quic", "dope", "o3", "rustls"],
    );
    let output = suite.try_build(&exe, env!("CARGO_PKG_NAME"))?.output()?;
    let suite = suite.try_collect(&exe, output)?;
    assert_eq!(
        suite.try_errors(include_str!("ownership_contracts.rs"))?,
        11
    );
    let status = suite.try_rustdoc()?.status()?;
    assert!(status.success(), "QUIC ownership contracts: {status}");
    Ok(())
}
