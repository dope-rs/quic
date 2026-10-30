pub mod common;

use common::suite::mux::{
    dispatch,
    paths::{self, CLIENT, Pair},
};
use common::suite::peers::packet::bytes;
use dope_quic::wire::frame;
use std::{net::SocketAddr, time::Duration};

#[test]
fn candidate_preserves_pto() {
    let (mut peer, mut server, handle, mut at) = paths::try_wire().expect("wire path fixture");
    let target = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let mut notice = peer
        .packet(&bytes::notice(65, 0).expect("spare CID"))
        .expect("spare CID packet");
    Pair::receive(&mut server, CLIENT, &mut notice, at).expect("spare CID announcement");
    let stream = Pair::access(&mut server, handle, at, |mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let id = send.open_uni().expect("stream credit");
        send.send(id, &[b'p'; 32_768]).expect("stream payload");
        send.finish(id).expect("stream FIN");
        id.id()
    })
    .expect("live connection");

    for _ in 0..32 {
        let (sent, window, ready) = Pair::access(&mut server, handle, at, |conn| {
            let view = conn.view();
            let state = view.recovery();
            (state.in_flight(), state.window(), state.send_at(at))
        })
        .expect("congestion state");
        if sent >= window {
            break;
        }
        at = ready;
        let flight = dispatch::Capture::output(&mut server, at).expect("fill congestion window");
        for mut packet in flight {
            for segment in packet.segments_mut() {
                if let Some(mut wire) = peer.receive(segment).expect("receive stream packet") {
                    peer.open(&mut wire).expect("open stream packet");
                }
            }
        }
    }
    let (sent, window, due, mtu) = Pair::access(&mut server, handle, at, |conn| {
        let view = conn.view();
        let state = view.recovery();
        (
            state.in_flight(),
            state.window(),
            state.next_timer().expect("unacknowledged stream PTO"),
            view.path().mtu() as usize,
        )
    })
    .expect("full congestion state");
    assert!(sent >= window, "flight {sent} must fill window {window}");
    assert!(due > at && due < at + Duration::from_secs(30));

    at += Duration::from_micros(1);
    assert!(at < due);
    let mut request = vec![frame::TYPE_PADDING; mtu];
    request[0] = frame::TYPE_PATH_CHALLENGE;
    request[1..9].copy_from_slice(b"pto-path");
    let mut wire = peer.packet(&request).expect("candidate challenge");
    let credit = wire.len() * 3;
    assert!(credit >= mtu, "candidate credit must fit one full packet");
    Pair::receive(&mut server, target, &mut wire, at).expect("candidate packet");
    let flight = dispatch::Capture::output(&mut server, at).expect("candidate staging");
    for mut packet in flight {
        let selected = packet.addr() == target;
        for segment in packet.segments_mut() {
            if let Some(mut wire) = peer.receive(segment).expect("receive staged packet") {
                peer.open(&mut wire).expect("open staged packet");
            }
            assert!(!selected, "full window must retain the candidate response");
        }
    }
    let (sent, window, timer) = Pair::access(&mut server, handle, at, |conn| {
        let view = conn.view();
        let state = view.recovery();
        (state.in_flight(), state.window(), state.next_timer())
    })
    .expect("staged congestion state");
    assert!(sent >= window);
    assert_eq!(timer, Some(due), "candidate must preserve the active PTO");

    let fired = due + Duration::from_nanos(1);
    let flight = dispatch::Capture::output(&mut server, fired).expect("active PTO output");
    let mut found = false;
    for mut packet in flight {
        let selected = packet.addr() == CLIENT;
        for segment in packet.segments_mut() {
            let Some(mut wire) = peer.receive(segment).expect("receive PTO packet") else {
                continue;
            };
            let (_, frames) = peer.open(&mut wire).expect("open PTO packet");
            for frame in frame::Frame::decode_all(&frames).expect("PTO frames") {
                found |= selected
                    && match frame.view() {
                        frame::View::Ping => true,
                        frame::View::Stream {
                            stream_id: id,
                            data,
                            ..
                        } => id == stream && !data.is_empty(),
                        _ => false,
                    };
            }
        }
    }
    assert!(
        found,
        "full window must still emit active PING or STREAM PTO"
    );
    assert!(server.handler().errors.is_empty());
}
