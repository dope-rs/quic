use crate::common::peer;
pub mod common;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use dope_quic::wire::frame::Borrowed;
use std::cell::Cell;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use dope_quic::proto::param;
use dope_quic::wire::packet::{QUIC_V1, long};
use dope_quic::wire::varint::VarInt;
use dope_quic::{conn, errors};
use long::initial;
use peer::sealer;

use common::suite::mux::dispatch::{CID, CLIENT, Capture, Count, SERVER};

#[test]
fn sealed_admission() {
    let (signing, key) = peer::raw(0x5a).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let mut server = Capture::server(
        Capture::default(),
        signing.server().expect("server TLS"),
        Options::try_from(params.clone())
            .expect("fixture configuration must satisfy its declared bounds"),
        Plan::standard(),
    )
    .expect("fixture server");
    let capture = Capture::default();
    let events = Rc::clone(&capture.events);
    let mut client = Builder::client(capture)
        .build()
        .expect("default client router resources must be valid");
    Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds"),
        CID.to_vec(),
        Instant::now(),
    )
    .expect("fixture connect");

    Pin::new(&mut server).seal();
    assert!(server.is_sealed());
    assert!(
        Capture::relay(&mut client, &mut server, CLIENT, Instant::now()).expect("fixture relay")
            > 0
    );
    assert_eq!(server.active_conns(), 0);
    assert!(events.borrow().established.is_empty());
    assert_eq!(events.borrow().certificates, 0);
    assert_eq!(server.handler().events.borrow().certificates, 0);
    for events in [&client.handler().events, &server.handler().events] {
        assert!(
            events
                .borrow()
                .owners
                .iter()
                .all(|(owner, handle)| owner == handle)
        );
    }
}

#[test]
fn invalid_initials() {
    let created = Rc::new(Cell::new(0));
    let mut server = Capture::server(
        Count {
            created: Rc::clone(&created),
            certificates: 0,
        },
        peer::raw(0x67)
            .expect("raw identity")
            .0
            .server()
            .expect("server TLS"),
        Options::default(),
        Plan::standard(),
    )
    .expect("fixture server");
    assert!(
        Pin::new(&mut server).config().try_resize(4).is_ok(),
        "four connection slots fit"
    );
    let now = Instant::now();

    for ordinal in 0_u8..16 {
        let dcid = [0xa0, ordinal, 2, 3, 4, 5, 6, 7];
        let scid = [0xb0, ordinal, 9, 10, 11, 12, 13, 14];
        let mut seal = sealer::Raw::initial(&dcid, rustls::Side::Client, 0)
            .expect("Initial client secret must form a packet sealer");
        let mut frames = Vec::new();
        Borrowed::crypto(VarInt::ZERO, &[ordinal; 16])
            .expect("bounded CRYPTO fields must form a frame")
            .encode(&mut frames)
            .expect("encode CRYPTO frame");
        let header = initial::Header {
            version: QUIC_V1,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            packet_number: 0,
            pn_len: 4,
        }
        .encode(frames.len())
        .expect("bounded Initial header and payload length must encode");
        let bytes = header.as_bytes();
        let mut wire = seal
            .seal(bytes, &frames, 0, bytes.len() - 4, 4)
            .expect("valid Initial inputs must seal");
        assert!(wire.len() < 1200, "proof packet must exercise §14.1");
        let original = wire.clone();

        Capture::recv(&mut server, CLIENT, &mut wire, now).expect("fixture recv");
        assert_eq!(wire, original, "pre-admission discard preserves storage");
    }

    let mut short = initial::Header {
        version: QUIC_V1,
        dcid: vec![0xcc; 8],
        scid: vec![0xdd; 8],
        token: Vec::new(),
        packet_number: 0,
        pn_len: 4,
    }
    .encode(4096)
    .expect("bounded Initial header must encode")
    .as_bytes()
    .to_vec();
    short.resize(1200, 0);
    Capture::recv(&mut server, CLIENT, &mut short, now).expect("fixture recv");

    assert_eq!(created.get(), 0, "handler authority was never constructed");
    assert_eq!(server.active_conns(), 0, "no slot was ever published");
    assert!(
        Capture::output(&mut server, now)
            .expect("fixture output")
            .is_empty()
    );
    assert_eq!(server.handler().certificates, 0);
}

#[test]
fn accept_flood() {
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 20)
        .try_build()
        .expect("fixture transport parameters");
    let mut server = Capture::server(
        Capture::default(),
        peer::raw(0x39)
            .expect("raw identity")
            .0
            .server()
            .expect("server TLS"),
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds"),
        Plan::standard(),
    )
    .expect("fixture server");
    assert!(
        Pin::new(&mut server).config().try_resize(4).is_ok(),
        "four connection slots fit"
    );

    let now = Instant::now();
    for index in 0u32..16 {
        let dcid = [
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            (index >> 8) as u8,
            index as u8,
            0x01,
            0x02,
        ];
        let scid = [0x10, 0x20, (index >> 8) as u8, index as u8];
        let mut seal = sealer::Raw::initial(&dcid, rustls::Side::Client, 0)
            .expect("Initial client secret must form a packet sealer");
        let mut frames = Vec::new();
        Borrowed::crypto(VarInt::ZERO, &[0u8; 16])
            .expect("bounded CRYPTO fields must form a frame")
            .encode(&mut frames)
            .expect("encode CRYPTO frame");
        frames.resize(1162, 0);
        let header = initial::Header {
            version: QUIC_V1,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            packet_number: 0,
            pn_len: 4,
        }
        .encode(frames.len())
        .expect("bounded flood Initial header must encode");
        let bytes = header.as_bytes();
        let mut wire = seal
            .seal(bytes, &frames, 0, bytes.len() - 4, 4)
            .expect("valid flood Initial inputs must seal");
        let from = SocketAddr::from(([10, 0, 0, (index % 250) as u8 + 1], 5000));
        let result = Pin::new(&mut server).observe(now, |mut turn| {
            turn.protocol().recv(from, &mut wire, epoch::WALL_CLOCK)
        });
        if index < 4 {
            assert!(matches!(
                result,
                Err(errors::Receive::Packet(conn::Error::Handshake(_)))
            ));
        } else {
            assert!(result.is_ok());
        }
    }

    assert_eq!(server.active_conns(), 4, "accept flood capped at max_conns");
    assert_eq!(server.handler().events.borrow().certificates, 0);
    assert!(
        server
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}
