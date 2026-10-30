pub mod common;

use common::suite::mux::{
    dispatch,
    paths::{self, CLIENT, Pair},
};
use common::suite::peers::packet::bytes;
use dope_quic::wire::frame;
use std::{net::SocketAddr, time::Duration};

#[test]
fn nonprobe_orders_path() {
    let target = SocketAddr::from(([10, 0, 0, 1], 50_001));
    for (kind, expected) in [(frame::TYPE_PING, CLIENT), (frame::TYPE_PADDING, target)] {
        let (mut peer, mut server, handle, start) = paths::try_wire().expect("wire path fixture");
        let at = start + Duration::from_millis(20);
        let mut notice = peer
            .packet(&bytes::notice(65, 0).expect("spare CID"))
            .expect("spare CID packet");
        Pair::receive(&mut server, CLIENT, &mut notice, at).expect("spare CID announcement");
        let mut payload = [0; 1_200];
        payload[0] = frame::TYPE_PING;
        let mut older = peer.packet(&payload).expect("older candidate packet");
        payload[0] = kind;
        let mut newer = peer.packet(&payload).expect("newer active packet");
        Pair::receive(&mut server, CLIENT, &mut newer, at).expect("active packet");
        Pair::receive(&mut server, target, &mut older, at).expect("reordered candidate packet");
        let flight = dispatch::Capture::output(&mut server, at).expect("validation challenge");
        let mut response =
            paths::try_response(&mut peer, flight, target).expect("probing response");
        Pair::receive(&mut server, target, &mut response, at).expect("path validation");
        assert_eq!(
            Pair::peer(&mut server, handle, at).expect("active path"),
            Some(expected)
        );
    }
}

#[test]
fn newer_active_wins() {
    let (mut peer, mut server, handle, start) = paths::try_wire().expect("wire path fixture");
    let target = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let at = start + Duration::from_millis(20);
    let mut notice = peer
        .packet(&bytes::notice(65, 0).expect("spare CID"))
        .expect("spare CID packet");
    Pair::receive(&mut server, CLIENT, &mut notice, at).expect("spare CID announcement");
    let mut ping = [0; 1_200];
    ping[0] = frame::TYPE_PING;
    let mut older = peer.packet(&ping).expect("older candidate packet");
    let mut newer = peer.packet(&ping).expect("newer active packet");
    Pair::receive(&mut server, target, &mut older, at).expect("candidate packet");
    Pair::receive(&mut server, CLIENT, &mut newer, at).expect("newer active packet");
    let flight = dispatch::Capture::output(&mut server, at).expect("validation challenge");
    let mut response = paths::try_response(&mut peer, flight, target).expect("probing response");
    Pair::receive(&mut server, target, &mut response, at).expect("path validation");
    assert_eq!(
        Pair::peer(&mut server, handle, at).expect("active path"),
        Some(CLIENT)
    );
}

#[test]
fn duplicate_keeps_pending() {
    let (mut peer, mut server, handle, start) = paths::try_wire().expect("wire path fixture");
    let target = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let other = SocketAddr::from(([10, 0, 0, 1], 50_002));
    let at = start + Duration::from_millis(20);
    for sequence in 65..68 {
        let mut notice = peer
            .packet(&bytes::notice(sequence, 0).expect("spare CID"))
            .expect("spare CID packet");
        Pair::receive(&mut server, CLIENT, &mut notice, at).expect("spare CID announcement");
    }
    let mut ping = [0; 1_200];
    ping[0] = frame::TYPE_PING;
    let mut accepted = peer.packet(&ping).expect("active packet");
    let mut replay = accepted.clone();
    Pair::receive(&mut server, CLIENT, &mut accepted, at).expect("active packet accepted");
    let mut intent = peer.packet(&ping).expect("candidate packet");
    Pair::receive(&mut server, target, &mut intent, at).expect("candidate intent");
    let flight = dispatch::Capture::output(&mut server, at).expect("validation challenge");
    let mut response = paths::try_response(&mut peer, flight, target).expect("probing response");
    Pair::receive(&mut server, other, &mut replay, at).expect("duplicate packet ignored");
    Pair::receive(&mut server, target, &mut response, at).expect("pending validation response");
    assert_eq!(
        Pair::peer(&mut server, handle, at).expect("validated path"),
        Some(target)
    );
}
