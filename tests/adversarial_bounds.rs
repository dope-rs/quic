pub mod support;

use std::time::Instant;

use dope_quic::early_data::EarlyDataReplayCache;
use dope_quic::frame::Frame;
use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};
use dope_quic::{Conn, ConnError, ConnectError, Handler, Mux, ServerConn, conn};

const INITIAL_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
const CLIENT_SCID: [u8; 4] = [1, 2, 3, 4];
const SERVER_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

fn server() -> ServerConn {
    Conn::new_server(
        INITIAL_DCID.to_vec(),
        SERVER_CID.to_vec(),
        CLIENT_SCID.to_vec(),
        support::signing_key(0x61),
        conn::Config::default(),
    )
    .unwrap()
}

#[test]
fn invalid_allocation_limits_fail_before_construction() {
    let config = conn::Config {
        max_pmtu: u64::MAX,
        ..Default::default()
    };
    assert_eq!(config.validate(), Err(ConnectError::InvalidConfig));
}

struct Noop;

impl Handler for Noop {}

#[test]
fn allocation_constructors_reject_unsupported_capacities() {
    assert!(EarlyDataReplayCache::with_capacity(usize::MAX).is_err());
    assert_eq!(
        Mux::client_with_limits(Noop, 0, 1, 1).err(),
        Some(ConnectError::InvalidConfig)
    );
    assert_eq!(
        Mux::client_with_limits(Noop, 1, usize::MAX, 1).err(),
        Some(ConnectError::InvalidConfig)
    );
    assert_eq!(
        Mux::client_with_limits(Noop, 1, 1, usize::MAX).err(),
        Some(ConnectError::InvalidConfig)
    );
}

#[test]
fn incoming_ack_ranges_are_bounded_before_iteration() {
    let mut server = server();
    let mut frames = Vec::new();
    Frame::Ack {
        largest: 600,
        delay: 0,
        first_range: 0,
        additional_ranges: vec![(0, 0); 257],
    }
    .encode(&mut frames)
    .unwrap();
    let packet = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, 0, &frames);
    assert_eq!(
        server.recv_packet(&packet, Instant::now()),
        Err(ConnError::FrameDecode)
    );
}

#[test]
fn fragmented_crypto_ranges_are_bounded_on_the_wire() {
    let mut server = server();
    let now = Instant::now();
    for packet_number in 0..=256 {
        let mut frames = Vec::new();
        Frame::Crypto {
            offset: packet_number * 2 + 1,
            data: vec![packet_number as u8],
        }
        .encode(&mut frames)
        .unwrap();
        let packet = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, packet_number, &frames);
        let result = server.recv_packet(&packet, now);
        if packet_number < 256 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(ConnError::CryptoBufferExceeded));
        }
    }
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
