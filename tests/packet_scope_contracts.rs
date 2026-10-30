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

#[test]
fn retains_packet_proofs() {
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
            .try_errors(&exe, include_str!("packet_scope_contracts.rs"))
            .expect("exact compiler errors"),
        4
    );
    let status = suite
        .try_rustdoc(&exe)
        .expect("rustdoc command")
        .status()
        .expect("compiler contracts");
    assert!(status.success(), "packet ownership contracts: {status}");
}
