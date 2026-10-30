pub mod common;
use common::suite::peers::{bounds, packet::bytes};
use std::time::Instant;

use dope_quic::wire::varint::VarInt;
use dope_test::alloc::Tracker;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn reuses_workspace() {
    let bounds::Server {
        conn: mut server,
        mut work,
    } = bounds::Server::try_new().expect("fixture server must open");
    let now = Instant::now();

    let mut first = bytes::sparse(0, VarInt::from_u8(1)).expect("first sparse packet must encode");
    let span = Tracker::begin();
    let result = server.with_scope(|mut scope| {
        scope
            .input(&mut work)
            .recv_packet(&mut first, now, |_: &rustls::Error| {})
    });
    let activity = span.finish();
    assert!(matches!(result, Ok(())));
    assert_eq!(activity.allocations, 1);

    for pn in 1..32 {
        let mut packet =
            bytes::sparse(pn, VarInt::from_u16(pn * 2 + 1)).expect("sparse packet must encode");
        let span = Tracker::begin();
        let result = server.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut packet, now, |_: &rustls::Error| {})
        });
        let activity = span.finish();
        assert!(matches!(result, Ok(())));
        assert_eq!(activity.allocations, 0, "range {pn} allocated");
    }
}
