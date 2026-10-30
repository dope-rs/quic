use crate::common::peer;
use common::suite::peers::tls;
use dope_quic::conn::life::options::Options;
use o3::buffer::storage;
pub mod common;
use common::suite::peers::bounds::{CLIENT_SCID, INITIAL_DCID, SERVER_CID, Server};

use std::time::Instant;

use dope_quic::conn::life::accept;
use dope_quic::conn::{self, Error};
use dope_quic::runtime::routing;
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::frame::decode::error;
use dope_quic::wire::frame::{self, Borrowed, Frame, View, close};
use dope_quic::wire::packet;
use dope_quic::wire::stream::Id;
use dope_quic::wire::varint::VarInt;
use packet::{cid, long};

#[test]
fn token_decode_bounds() {
    let wire = [frame::TYPE_NEW_TOKEN, 3, 0x91, 0x92, 0x93];
    let frame = Frame::decode_all(&wire).expect("nonempty NEW_TOKEN fixture decodes");
    let mut encoded = Vec::new();
    for item in &frame {
        item.encode(&mut encoded).expect("wire encoding");
    }
    assert_eq!(encoded, wire);

    let mut bad = vec![frame::TYPE_NEW_TOKEN];
    VarInt::ZERO.encode(&mut bad).expect("wire encoding");
    assert!(matches!(
        Frame::decode_all(&bad),
        Err(error::Error::Fault(error::Fault::InvalidToken {
            length: 0
        }))
    ));
}

#[test]
fn ack_range_bound() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let mut frames = vec![frame::TYPE_ACK];
    VarInt::new(600)
        .expect("bounded fixture integer")
        .encode(&mut frames)
        .expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    VarInt::new(257)
        .expect("bounded fixture integer")
        .encode(&mut frames)
        .expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    for _ in 0..257 {
        VarInt::ZERO.encode(&mut frames).expect("wire encoding");
        VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    }
    let packet = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&frames);
    let mut packet = (packet).expect("test precondition");
    assert!(matches!(
        server.with_scope(|mut scope| scope.input(&mut work).recv_packet(
            &mut packet,
            Instant::now(),
            |_: &rustls::Error| {}
        )),
        Err(Error::Frame(error::Fault::AckCount {
            actual: 257,
            maximum: 256
        }))
    ));
}

/// The first additional span is valid: 8..=8. The second gap would
/// underflow below packet number zero and must invalidate the whole frame.
#[test]
fn ack_underflow() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let mut frames = vec![frame::TYPE_ACK];
    VarInt::new(10)
        .expect("bounded fixture integer")
        .encode(&mut frames)
        .expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    VarInt::new(2)
        .expect("bounded fixture integer")
        .encode(&mut frames)
        .expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");
    VarInt::new(7)
        .expect("bounded fixture integer")
        .encode(&mut frames)
        .expect("wire encoding");
    VarInt::ZERO.encode(&mut frames).expect("wire encoding");

    let packet = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&frames);
    let mut packet = (packet).expect("test precondition");
    assert!(matches!(
        server.with_scope(|mut scope| scope.input(&mut work).recv_packet(
            &mut packet,
            Instant::now(),
            |_: &rustls::Error| {}
        )),
        Err(Error::Frame(error::Fault::AckGap {
            previous_smallest: 8,
            gap: 7
        }))
    ));
    assert!(
        !server.view().lifecycle().is_closed(),
        "malformed ACK closes transactionally through the pending close lane"
    );
}

#[test]
fn ack_topology() {
    assert!(matches!(
        Borrowed::ack(
            VarInt::ZERO,
            VarInt::ZERO,
            VarInt::new(1).expect("bounded fixture integer"),
            &[]
        ),
        Err(error::Fault::AckFirst {
            largest: 0,
            range: 1
        })
    ));

    let mut wire = vec![frame::TYPE_ACK];
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");
    VarInt::new(1)
        .expect("bounded fixture integer")
        .encode(&mut wire)
        .expect("wire encoding");
    assert!(matches!(
        Frame::decode(&wire),
        Err(error::Error::Fault(error::Fault::AckFirst {
            largest: 0,
            range: 1
        }))
    ));
}

#[test]
fn frame_fields() {
    assert!(matches!(
        Frame::decode(&[frame::TYPE_NEW_TOKEN, 0]),
        Err(error::Error::Fault(error::Fault::InvalidToken {
            length: 0
        }))
    ));
    assert!(matches!(
        Frame::decode(&[frame::TYPE_NEW_CONNECTION_ID, 0, 0, 0]),
        Err(error::Error::Fault(error::Fault::InvalidConnectionId {
            sequence_number: 0,
            retire_prior_to: 0,
            length: 0
        }))
    ));
    assert!(matches!(
        Frame::decode(&[frame::TYPE_NEW_CONNECTION_ID, 0, 0, 21]),
        Err(error::Error::Fault(error::Fault::Underflow {
            offset: 4,
            actual: 0,
            required: 37
        }))
    ));
    assert!(matches!(
        Frame::decode(&[
            frame::TYPE_NEW_CONNECTION_ID,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]),
        Err(error::Error::Fault(error::Fault::InvalidConnectionId {
            sequence_number: 0,
            retire_prior_to: 1,
            length: 1
        }))
    ));
    assert!(matches!(
        Borrowed::stream(
            Id::ZERO,
            VarInt::MAX_VALUE,
            frame::Boundary::More,
            frame::Length::Explicit,
            &[1]
        ),
        Err(error::Fault::InvalidLength {
            offset: VarInt::MAX,
            length: 1
        })
    ));
    assert!(matches!(
        Frame::decode(&[frame::TYPE_MAX_STREAMS_BIDI, 0xd0, 0, 0, 0, 0, 0, 0, 1]),
        Err(error::Error::Fault(error::Fault::InvalidStreamCount { value }))
            if value == (1u64 << 60) + 1
    ));
}

#[test]
fn stream_output_unchanged() {
    let mut wire = vec![0xaa, 0xbb];
    assert!(matches!(
        Borrowed::stream(
            Id::ZERO,
            VarInt::MAX_VALUE,
            frame::Boundary::More,
            frame::Length::Explicit,
            &[1]
        )
        .map(|frame| frame.encode(&mut wire)),
        Err(error::Fault::InvalidLength {
            offset: VarInt::MAX,
            length: 1
        })
    ));
    assert_eq!(wire, [0xaa, 0xbb]);
}

#[test]
fn initial_frame_rejected() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let mut frames = Vec::new();
    Borrowed::stream(
        Id::ZERO,
        VarInt::ZERO,
        frame::Boundary::More,
        frame::Length::Explicit,
        b"not legal in Initial",
    )
    .expect("bounded stream fields must form a STREAM frame")
    .encode(&mut frames)
    .expect("wire encoding");
    let packet = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&frames);
    let mut packet = (packet).expect("test precondition");

    assert!(matches!(
        server.with_scope(|mut scope| scope.input(&mut work).recv_packet(
            &mut packet,
            Instant::now(),
            |_: &rustls::Error| {}
        )),
        Err(Error::ProtocolViolation)
    ));
    assert!(
        !server.view().lifecycle().is_closed(),
        "close is pending until it reaches the wire"
    );

    let (emitted_packets, send_result) =
        server.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("configured server journals must admit CONNECTION_CLOSE");
    let close = emitted_packets
        .into_iter()
        .next()
        .expect("authenticated violations emit CONNECTION_CLOSE");
    let guard = Initial::try_new(&INITIAL_DCID)
        .expect("initial derivation")
        .try_server()
        .expect("server key admission");
    let packet = {
        match long::Parsed::parse(close).expect("server close datagram must contain a long packet")
        {
            long::Parsed::Initial(packet) => Some(packet),
            _ => None,
        }
        .expect("server close refined to a 0-RTT packet")
    };
    let opened = packet
        .decrypt(&guard, 0)
        .expect("server Initial close must decrypt with server Initial keys");
    let frames = Frame::decode_all(opened.body()).expect("decrypted close frames must decode");
    assert!(matches!(
        frames.first().map(Frame::view),
        Some(View::ConnectionClose {
            code: close::Code::Transport {
                error_code,
                frame_type,
            },
            ..
        }) if error_code.get() == 0x0a && frame_type == VarInt::ZERO
    ));
    assert!(server.view().lifecycle().is_closed());
}

#[test]
fn fixed_bit_discarded() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let packet = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&[frame::TYPE_PING]);
    let mut packet = (packet).expect("test precondition");
    packet[0] &= !packet::FIXED_BIT;

    assert!(matches!(
        server.with_scope(|mut scope| scope.input(&mut work).recv_packet(
            &mut packet,
            Instant::now(),
            |_: &rustls::Error| {}
        )),
        Ok(())
    ));
    assert!(server.view().lifecycle().is_opening());
}

#[test]
fn crypto_range_bound() {
    let Server {
        conn: mut server,
        mut work,
    } = Server::try_new().expect("adversarial fixture server must open");
    let now = Instant::now();
    for number in 0..=256 {
        let mut frames = Vec::new();
        Borrowed::crypto(
            VarInt::new(number * 2 + 1).expect("bounded fixture integer"),
            &[number as u8],
        )
        .expect("bounded CRYPTO fields must form a frame")
        .encode(&mut frames)
        .expect("wire encoding");
        let packet = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, number).seal(&frames);
        let mut packet = (packet).expect("test precondition");
        let result = server.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut packet, now, |_: &rustls::Error| {})
        });
        if number < 256 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::CryptoBufferExceeded)));
        }
    }
}

#[test]
fn crypto_reassembly() {
    let (signing, key) = peer::raw(0x61).expect("raw identity");
    let config = signing.server().expect("server TLS");
    let mut client = tls::client(key)
        .expect("client TLS authority")
        .connect::<0, Vec<u8>, storage::Shared>(
            cid::Id::try_from(INITIAL_DCID).expect("bounded fixture CID"),
            cid::Id::try_from(CLIENT_SCID).expect("bounded fixture CID"),
            Options::default(),
            routing::Plain,
        )
        .expect("valid identifiers and default options must start a client connection");
    let now = Instant::now();
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let (emitted_packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("configured client journals must admit the Initial");
    let original = emitted_packets.into_iter().next().expect("client Initial");
    let guard = Initial::try_new(&INITIAL_DCID)
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let packet = {
        match long::Parsed::parse(original).expect("client datagram must contain a long packet") {
            long::Parsed::Initial(packet) => Some(packet),
            _ => None,
        }
        .expect("client Initial refined to a 0-RTT packet")
    };
    let opened = packet
        .decrypt(&guard, 0)
        .expect("client Initial must decrypt with client Initial keys");
    let crypto = Frame::decode_all(opened.body())
        .expect("decrypted client Initial frames must decode")
        .into_iter()
        .find_map(|frame| match frame.view() {
            View::Crypto { offset, data } if offset == VarInt::ZERO => Some(data.clone()),
            _ => None,
        })
        .expect("ClientHello CRYPTO frame");
    assert!(crypto.len() > 2);

    for pending in [false, true] {
        let ids = accept::Ids::initial(
            cid::Id::try_from(INITIAL_DCID).expect("bounded fixture CID"),
            cid::Id::try_from(SERVER_CID).expect("bounded fixture CID"),
            cid::Id::try_from(CLIENT_SCID).expect("bounded fixture CID"),
        );
        let mut server: conn::Connection =
            accept::Authority::new(config.clone(), Options::default())
                .expect("test key and default options must form a server authority")
                .accept::<storage::Shared>(ids)
                .expect("valid initial identifiers must start a server connection");
        let mut suffix = crypto[2..].to_vec();
        if pending {
            suffix.push(0xff);
        }
        let mut tail = Vec::new();
        Borrowed::crypto(VarInt::new(2).expect("bounded fixture integer"), &suffix)
            .expect("bounded CRYPTO tail must form a frame")
            .encode(&mut tail)
            .expect("wire encoding");
        let tail = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&tail);
        let mut tail = tail.expect("test precondition");
        let result = server.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut tail, now, |_: &rustls::Error| {})
        });
        assert!(
            result.is_ok(),
            "out-of-order CRYPTO tail must remain buffered: {result:?}"
        );

        let mut prefix = Vec::new();
        Borrowed::crypto(VarInt::ZERO, &crypto[..2])
            .expect("bounded CRYPTO prefix must form a frame")
            .encode(&mut prefix)
            .expect("wire encoding");
        let prefix = peer::Initial::new(&INITIAL_DCID, &CLIENT_SCID, 1).seal(&prefix);
        let mut prefix = prefix.expect("test precondition");
        let result = server.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut prefix, now, |_: &rustls::Error| {})
        });
        if pending {
            assert!(
                matches!(
                    &result,
                    Err(Error::Handshake(cause))
                        if matches!(
                            &cause.error,
                            rustls::Error::PeerMisbehaved(
                                rustls::PeerMisbehaved::KeyEpochWithPendingFragment
                            )
                        ) && cause.alert == Some(rustls::AlertDescription::UnexpectedMessage)
                ),
                "pending Initial fragment must prevent TLS key change: {result:?}"
            );
        } else {
            assert!(
                result.is_ok(),
                "CRYPTO prefix must close the buffered range gap: {result:?}"
            );
            assert!(
                {
                    let (emitted_packets, send_result) =
                        server.with_scope(|mut scope| scope.output().send(now));
                    send_result.expect("configured server journals must admit handshake flights");
                    emitted_packets
                }
                .len()
                    >= 2,
                "closing the offset gap must drive ClientHello into the Initial and Handshake flights"
            );
        }
    }
}
