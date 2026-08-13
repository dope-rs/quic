pub mod support;

use std::time::Instant;

use dope_quic::conn::Error;
use dope_quic::conn::server;
use dope_quic::early_data::EarlyDataReplayCache;
use dope_quic::frame::Frame;
use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};
use dope_quic::varint::VarInt;
use dope_quic::{ConnectError, Handler, conn, conn::session::Connection};

const INITIAL_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
const CLIENT_SCID: [u8; 4] = [1, 2, 3, 4];
const SERVER_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

fn server() -> server::Connection {
    dope_quic::conn::setup::Server::<0>::accept(
        INITIAL_DCID.to_vec(),
        SERVER_CID.to_vec(),
        CLIENT_SCID.to_vec(),
        support::signing_key(0x61),
        conn::config::Options::default(),
    )
    .unwrap()
}

#[test]
fn invalid_allocation_limits_fail_before_construction() {
    let config = conn::config::Options {
        max_pmtu: u64::MAX,
        ..Default::default()
    };
    assert_eq!(config.validate(), Err(ConnectError::InvalidConfig));

    let config = conn::config::Options {
        local_bidi_stream_capacity: 65_537,
        ..Default::default()
    };
    assert_eq!(config.validate(), Err(ConnectError::InvalidConfig));

    let config = conn::config::Options {
        local_uni_stream_capacity: 65_537,
        ..Default::default()
    };
    assert_eq!(config.validate(), Err(ConnectError::InvalidConfig));
}

struct Noop;

impl Handler<0> for Noop {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: dope_quic::conn::Handle) {}
}

#[test]
fn allocation_constructors_reject_unsupported_capacities() {
    assert!(EarlyDataReplayCache::with_capacity(usize::MAX).is_err());
    assert_eq!(
        dope_quic::mux::setup::Client::new(Noop)
            .limits(0, 1, 1)
            .build()
            .err(),
        Some(ConnectError::InvalidConfig)
    );
    assert_eq!(
        dope_quic::mux::setup::Client::new(Noop)
            .limits(1, usize::MAX, 1)
            .build()
            .err(),
        Some(ConnectError::InvalidConfig)
    );
    assert_eq!(
        dope_quic::mux::setup::Client::new(Noop)
            .limits(1, 1, usize::MAX)
            .build()
            .err(),
        Some(ConnectError::InvalidConfig)
    );
}

#[test]
fn incoming_ack_ranges_are_bounded_before_iteration() {
    let mut server = server();
    let mut workspace = conn::ReceiveWorkspace::new();
    let mut frames = Vec::new();
    Frame::Ack {
        largest: VarInt::new(600).unwrap(),
        delay: VarInt::ZERO,
        first_range: VarInt::ZERO,
        additional_ranges: vec![(VarInt::ZERO, VarInt::ZERO); 257],
    }
    .encode(&mut frames)
    .unwrap();
    let mut packet = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, 0, &frames);
    assert_eq!(
        server.recv_packet(&mut workspace, &mut packet, Instant::now()),
        Err(Error::FrameDecode)
    );
}

#[test]
fn fragmented_crypto_ranges_are_bounded_on_the_wire() {
    let mut server = server();
    let mut workspace = conn::ReceiveWorkspace::new();
    let now = Instant::now();
    for packet_number in 0..=256 {
        let mut frames = Vec::new();
        Frame::Crypto {
            offset: VarInt::new(packet_number * 2 + 1).unwrap(),
            data: vec![packet_number as u8],
        }
        .encode(&mut frames)
        .unwrap();
        let mut packet =
            support::client_initial(&INITIAL_DCID, &CLIENT_SCID, packet_number, &frames);
        let result = server.recv_packet(&mut workspace, &mut packet, now);
        if packet_number < 256 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(Error::CryptoBufferExceeded));
        }
    }
}

#[test]
fn out_of_order_crypto_closes_directly_into_one_handshake_message() {
    let signing = support::signing_key(0x61);
    let public_key = *signing.pubkey().unwrap();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        INITIAL_DCID.to_vec(),
        SERVER_CID.to_vec(),
        CLIENT_SCID.to_vec(),
        signing,
        conn::config::Options::default(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        INITIAL_DCID.to_vec(),
        CLIENT_SCID.to_vec(),
        public_key,
        conn::config::Options::default(),
    )
    .unwrap();
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    let mut original = client
        .transmit()
        .send(now)
        .into_iter()
        .next()
        .expect("client Initial");
    let pn_offset = InitialHeader::decode_pre_hp(&original).unwrap().pn_offset;
    let protection = PacketProtection::aes_128(
        &PacketKeys::aes_128(&InitialSecrets::from_dcid(&INITIAL_DCID).unwrap().client).unwrap(),
    )
    .unwrap();
    let (_, plaintext) = protection
        .decrypt_long_in_place(&mut original, pn_offset, 0)
        .unwrap();
    let crypto = Frame::decode_all(&original[plaintext])
        .unwrap()
        .into_iter()
        .find_map(|frame| match frame {
            Frame::Crypto { offset, data } if offset == VarInt::ZERO => Some(data),
            _ => None,
        })
        .expect("ClientHello CRYPTO frame");
    assert!(crypto.len() > 2);

    let mut tail = Vec::new();
    Frame::Crypto {
        offset: VarInt::new(2).unwrap(),
        data: crypto[2..].to_vec(),
    }
    .encode(&mut tail)
    .unwrap();
    let mut tail = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, 0, &tail);
    server.recv_packet(&mut workspace, &mut tail, now).unwrap();

    let mut prefix = Vec::new();
    Frame::Crypto {
        offset: VarInt::ZERO,
        data: crypto[..2].to_vec(),
    }
    .encode(&mut prefix)
    .unwrap();
    let mut prefix = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, 1, &prefix);
    server
        .recv_packet(&mut workspace, &mut prefix, now)
        .unwrap();

    assert!(
        server.transmit().send(now).len() >= 2,
        "closing the offset gap must drive ClientHello into the Initial and Handshake flights"
    );
}

#[test]
fn packet_number_reconstruction_crosses_four_byte_boundary() {
    let packet_number = 1u64 << 32;
    let secrets = InitialSecrets::from_dcid(&INITIAL_DCID).unwrap();
    let keys = PacketKeys::aes_128(&secrets.client).unwrap();
    let protection = PacketProtection::aes_128(&keys).unwrap();
    let header = InitialHeader {
        version: QUIC_V1,
        dcid: INITIAL_DCID.to_vec(),
        scid: CLIENT_SCID.to_vec(),
        token: Vec::new(),
        packet_number,
        pn_len: 4,
    };
    let payload = vec![0x01; 32];
    let (header, pn_offset) = header.encode_with_pn(payload.len() + 16).unwrap();
    let mut wire = protection
        .encrypt_long(&header, &payload, packet_number, pn_offset, 4)
        .unwrap();
    let (decoded, plaintext) = protection
        .decrypt_long_in_place(&mut wire, pn_offset, packet_number)
        .unwrap();
    assert_eq!(decoded, packet_number);
    assert_eq!(&wire[plaintext], payload);
}
