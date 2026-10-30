pub mod common;

use common::suite::mux::{
    dispatch,
    paths::{self, CLIENT, Pair},
};
use common::suite::peers::packet::{CID, bytes};
use dope_quic::{
    conn::output::transmit,
    wire::{frame, varint::VarInt},
};
use o3::depot::capacity;
use std::{iter, net::SocketAddr, time::Duration};

#[test]
fn retains_retired_cid() {
    let (mut peer, mut server, handle, start) = paths::try_wire().expect("wire path fixture");

    let notice = bytes::notice(65, 0).expect("sparse CID announcement");
    let at = start + Duration::from_millis(20);
    Pair::receive(
        &mut server,
        CLIENT,
        &mut peer.packet(&notice).expect("first CID announcements"),
        at,
    )
    .expect("CID ingress");
    let mut probe = [0; 1_200];
    probe[0] = frame::TYPE_PING;
    let first = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let second = SocketAddr::from(([10, 0, 0, 1], 50_002));
    Pair::receive(
        &mut server,
        first,
        &mut peer.packet(&probe).expect("first candidate packet"),
        at,
    )
    .expect("first candidate ingress");
    let flight = dispatch::Capture::output(&mut server, at).expect("first candidate output");
    let retired = Pair::path(&flight, first)
        .find_map(Pair::short_cid)
        .expect("first candidate uses a spare connection ID")
        .to_vec();
    assert_eq!(retired, [0x59, 65, 0, 0, 0, 0, 0, 0]);
    for mut packet in flight {
        for segment in packet.segments_mut() {
            if let Some(mut wire) = peer.receive(segment).expect("first candidate packet") {
                peer.open(&mut wire).expect("authenticated first candidate");
            }
        }
    }

    let expired = at + Duration::from_secs(5);
    for (now, expected) in [
        (expired, &[65][..]),
        (expired + Duration::from_millis(1), &[1, 65][..]),
    ] {
        if now != expired {
            for sequence in [65, 1, 1] {
                let notice = bytes::notice(sequence, 0).expect("delayed CID announcement");
                Pair::receive(
                    &mut server,
                    CLIENT,
                    &mut peer.packet(&notice).expect("delayed CID packet"),
                    now,
                )
                .expect("delayed CID ingress");
            }
        }
        let mut output =
            dispatch::Capture::output(&mut server, now).expect("candidate retirement output");
        assert!(Pair::path(&output, first).next().is_none());
        let mut seqs = Vec::new();
        let mut ack = Vec::new();
        for packet in &mut output {
            assert_eq!(packet.addr(), CLIENT);
            assert_eq!(Pair::short_cid(packet), Some(CID.as_slice()));
            for segment in packet.segments_mut() {
                let (number, data) = peer.open(segment).expect("authenticated retirement");
                for frame in frame::Frame::decode_all(&data).expect("retirement frames") {
                    if let frame::View::RetireConnectionId {
                        sequence_number: seq,
                    } = frame.view()
                    {
                        seqs.push(seq.get());
                    }
                }
                frame::Borrowed::ack(
                    VarInt::try_from(number).expect("packet number"),
                    VarInt::ZERO,
                    VarInt::ZERO,
                    &[],
                )
                .expect("retirement acknowledgement")
                .encode(&mut ack)
                .expect("ACK encoding");
            }
        }
        seqs.sort_unstable();
        assert_eq!(seqs.as_slice(), expected);
        Pair::receive(
            &mut server,
            CLIENT,
            &mut peer.packet(&ack).expect("retirement ACK packet"),
            now,
        )
        .expect("retirement ACK ingress");
        let conn = server.conn(handle).expect("original connection survives");
        assert!(conn.view().lifecycle().is_ready());
        assert_eq!(conn.view().path().peer_address(), Some(CLIENT));
    }

    let replayed = expired + Duration::from_millis(2);
    let notice = bytes::notice(66, 0).expect("fresh CID announcement");
    Pair::receive(
        &mut server,
        CLIENT,
        &mut peer.packet(&notice).expect("fresh CID packet"),
        replayed,
    )
    .expect("fresh CID ingress");
    let at = replayed + Duration::from_millis(1);
    Pair::receive(
        &mut server,
        second,
        &mut peer.packet(&probe).expect("second candidate packet"),
        at,
    )
    .expect("second candidate ingress");
    let flight = dispatch::Capture::output(&mut server, at).expect("second candidate output");
    let next = Pair::path(&flight, second)
        .find_map(Pair::short_cid)
        .expect("second candidate uses an available connection ID")
        .to_vec();
    assert_ne!(next, retired, "retired IDs cannot be used again");
    assert_eq!(next, [0x59, 66, 0, 0, 0, 0, 0, 0]);
    for mut packet in flight {
        for segment in packet.segments_mut() {
            if let Some(mut wire) = peer.receive(segment).expect("second candidate packet") {
                peer.open(&mut wire)
                    .expect("authenticated second candidate");
            }
        }
    }

    let ended = at + Duration::from_secs(5);
    let filled = ended + Duration::from_millis(1);
    let mut seqs = Vec::new();
    for (now, range) in [(ended, 0..0), (filled, 67..130)] {
        for sequence in range {
            let notice = bytes::notice(sequence, sequence).expect("issued CID rotation");
            Pair::receive(
                &mut server,
                CLIENT,
                &mut peer.packet(&notice).expect("CID rotation packet"),
                now,
            )
            .expect("issued CID rotation ingress");
        }
        let mut output =
            dispatch::Capture::output(&mut server, now).expect("issued retirement output");
        assert!(Pair::path(&output, second).next().is_none());
        let active = if now == ended {
            CID
        } else {
            [0x59, 129, 0, 0, 0, 0, 0, 0]
        };
        for packet in &mut output {
            assert_eq!(packet.addr(), CLIENT);
            assert_eq!(Pair::short_cid(packet), Some(active.as_slice()));
            for segment in packet.segments_mut() {
                let (_, data) = peer.open(segment).expect("authenticated issued retirement");
                for frame in frame::Frame::decode_all(&data).expect("issued retirement frames") {
                    if let frame::View::RetireConnectionId {
                        sequence_number: seq,
                    } = frame.view()
                    {
                        seqs.push(seq.get());
                    }
                }
            }
        }
        if now == ended {
            assert_eq!(seqs, [66]);
        }
    }
    seqs.sort_unstable();
    assert_eq!(seqs, iter::once(0).chain(66..=128).collect::<Vec<_>>());

    let at = filled + Duration::from_millis(1);
    let notice = bytes::notice(130, 129).expect("fresh spare CID");
    Pair::receive(
        &mut server,
        CLIENT,
        &mut peer.packet(&notice).expect("spare CID packet"),
        at,
    )
    .expect("spare CID ingress");
    let third = SocketAddr::from(([10, 0, 0, 1], 50_003));
    Pair::receive(
        &mut server,
        third,
        &mut peer.packet(&probe).expect("third candidate packet"),
        at,
    )
    .expect("third candidate ingress");
    let flight = dispatch::Capture::output(&mut server, at).expect("third candidate output");
    assert_eq!(
        Pair::path(&flight, third).find_map(Pair::short_cid),
        Some([0x59, 130, 0, 0, 0, 0, 0, 0].as_slice())
    );
    for mut packet in flight {
        for segment in packet.segments_mut() {
            if let Some(mut wire) = peer.receive(segment).expect("third candidate packet") {
                peer.open(&mut wire).expect("authenticated third candidate");
            }
        }
    }
    let error = dispatch::Capture::output(&mut server, at + Duration::from_secs(5))
        .err()
        .expect("full retirement must be reported");
    let (actual, cause) = error.into_parts();
    assert_eq!(actual, handle);
    assert_eq!(cause, transmit::Error::Path(capacity::Reason::Full));
    assert!(
        server.handler().errors.is_empty(),
        "{:?}",
        server.handler().errors
    );
}
