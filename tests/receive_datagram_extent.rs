pub mod common;

use common::suite::peers::packet::{Pair, bytes};
use dope_quic::{conn::Error, proto::param};
use std::time::Instant;

#[test]
fn uses_consumed_extent() {
    for maximum in [4, 3] {
        let now = Instant::now();
        let params = param::Set::builder()
            .datagram(Some(maximum))
            .try_build()
            .expect("datagram limit");
        let mut pair =
            Pair::try_params(1, params, now, |_| {}).expect("independent peer handshake");
        let mut packet = pair
            .peer
            .packet(bytes::DATAGRAM_WIDE)
            .expect("datagram packet");
        let result = pair.server.with_scope(|mut scope| {
            scope
                .input(&mut pair.work)
                .recv_packet(&mut packet, now, |_| {})
        });
        if maximum == 4 {
            result.expect("exact frame limit");
        } else {
            assert!(matches!(result, Err(Error::ProtocolViolation)));
        }
        let received = pair.server.with_scope(|mut scope| scope.datagrams().recv());
        assert_eq!(
            received.as_deref(),
            (maximum == 4).then_some(bytes::DATAGRAM_PAYLOAD),
        );
    }
}
