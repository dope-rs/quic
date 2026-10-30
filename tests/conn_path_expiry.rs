pub mod common;

use common::suite::mux::{
    dispatch,
    paths::{self, CLIENT, Pair},
};
use common::suite::peers::packet::bytes;
use dope_quic::wire::frame;
use std::{net::SocketAddr, time::Duration};

#[test]
fn expired_response_keeps() {
    let (mut peer, mut server, handle, at) = paths::try_wire().expect("wire path fixture");
    let target = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let mut notice = peer
        .packet(&bytes::notice(65, 0).expect("spare CID"))
        .expect("spare CID packet");
    Pair::receive(&mut server, CLIENT, &mut notice, at).expect("spare CID announcement");
    let mut request = Vec::new();
    for token in 0_u64..17 {
        request.push(frame::TYPE_PATH_CHALLENGE);
        request.extend_from_slice(&token.to_be_bytes());
    }
    let mut wire = peer.packet(&request).expect("candidate challenges");
    let credit = wire.len() * 3;
    assert!(credit < 1_200);
    Pair::receive(&mut server, target, &mut wire, at).expect("candidate packet");
    let flight = dispatch::Capture::output(&mut server, at).expect("candidate responses");
    let mut sent = 0;
    let mut replies = Vec::new();
    for mut packet in flight {
        let selected = packet.addr() == target;
        for segment in packet.segments_mut() {
            if selected {
                sent += segment.len();
            }
            let Some(mut wire) = peer.receive(segment).expect("receive server packet") else {
                assert!(!selected, "candidate packet must contain 1-RTT frames");
                continue;
            };
            let (_, frames) = peer.open(&mut wire).expect("open server packet");
            if !selected {
                continue;
            }
            for frame in frame::Frame::decode_all(&frames).expect("response frames") {
                if let frame::View::PathResponse { data } = frame.view() {
                    replies.push(u64::from_be_bytes(*data));
                }
            }
        }
    }
    assert_eq!(sent, credit);
    replies.sort_unstable();
    let pending = (0_u64..17)
        .find(|token| !replies.contains(token))
        .expect("one response remains queued");
    assert_eq!(
        replies,
        (0_u64..17)
            .filter(|token| *token != pending)
            .collect::<Vec<_>>()
    );

    let expired = at + Duration::from_secs(5);
    let stream = Pair::access(&mut server, handle, expired, |mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let id = send.open_uni().expect("active stream credit");
        send.send(id, b"active-after-expiry")
            .expect("active stream payload");
        send.finish(id).expect("active stream FIN");
        id.id()
    })
    .expect("live active connection");
    let flight = dispatch::Capture::output(&mut server, expired).expect("expired candidate");
    let mut found = false;
    for mut packet in flight {
        let selected = packet.addr() == CLIENT;
        for segment in packet.segments_mut() {
            let Some(mut wire) = peer.receive(segment).expect("receive active packet") else {
                continue;
            };
            let (_, frames) = peer.open(&mut wire).expect("open active packet");
            if !selected {
                continue;
            }
            for frame in frame::Frame::decode_all(&frames).expect("active frames") {
                found |= matches!(
                    frame.view(),
                    frame::View::Stream { stream_id: id, data, .. }
                        if id == stream && data.as_slice() == b"active-after-expiry"
                );
            }
        }
    }
    assert!(found, "expired candidate must not block the active stream");

    let mut wire = peer
        .packet(&[frame::TYPE_PADDING])
        .expect("fresh old-route credit");
    Pair::receive(&mut server, target, &mut wire, expired).expect("old-route padding");
    let flight = dispatch::Capture::output(&mut server, expired).expect("retained response");
    replies.clear();
    for mut packet in flight {
        let selected = packet.addr() == target;
        for segment in packet.segments_mut() {
            let Some(mut wire) = peer.receive(segment).expect("receive retained response") else {
                assert!(!selected, "response packet must contain 1-RTT frames");
                continue;
            };
            let (_, frames) = peer.open(&mut wire).expect("open retained response");
            if !selected {
                continue;
            }
            for frame in frame::Frame::decode_all(&frames).expect("retained frames") {
                if let frame::View::PathResponse { data } = frame.view() {
                    replies.push(u64::from_be_bytes(*data));
                }
            }
        }
    }
    assert_eq!(replies, vec![pending]);
    assert!(server.handler().errors.is_empty());
}
