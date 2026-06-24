use std::time::Instant;

use dope_quic::frame::Frame;
use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::packet_protection::PacketProtection;
use dope_quic::qkdf::{InitialSecrets, PacketKeys};
use dope_quic::{Conn, ConnConfig, ConnError, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const HS_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

fn handshake_pair_with_credit(stream_credit: u64, conn_credit: u64) -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let cfg = || ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            initial_max_data: conn_credit,
            initial_max_stream_data_bidi_local: stream_credit,
            initial_max_stream_data_bidi_remote: stream_credit,
            initial_max_stream_data_uni: stream_credit,
            initial_max_streams_bidi: 8,
            initial_max_streams_uni: 8,
            ..transport_params::Params::default()
        },
        ..Default::default()
    };
    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing,
        cfg(),
    );
    let mut client = Conn::new_client(HS_CID.to_vec(), HS_CID.to_vec(), server_pubkey, cfg());
    let now = Instant::now();
    for _ in 0..3 {
        for pkt in client.send_packets(now) {
            server.recv_packet(&pkt, now).expect("server recv");
        }
        for pkt in server.send_packets(now) {
            client.recv_packet(&pkt, now).expect("client recv");
        }
    }
    assert!(client.is_established() && server.is_established());
    (server, client)
}

#[test]
fn stream_data_over_per_stream_window_is_flow_control_error() {
    let (mut server, mut client) = handshake_pair_with_credit(8, 1 << 30);
    let now = Instant::now();
    let frame = Frame::Stream {
        stream_id: 0,
        offset: 0,
        fin: false,
        length_prefixed: true,
        data: vec![0u8; 4096],
    };
    let wire = forge_one_rtt(&mut client, frame, now);
    let err = server.recv_packet(&wire, now).unwrap_err();
    assert_eq!(err, ConnError::FlowControl);
}

#[test]
fn stream_offset_over_connection_window_is_flow_control_error() {
    let (mut server, mut client) = handshake_pair_with_credit(1 << 30, 16);
    let now = Instant::now();
    let frame = Frame::Stream {
        stream_id: 0,
        offset: 0,
        fin: false,
        length_prefixed: true,
        data: vec![0u8; 4096],
    };
    let wire = forge_one_rtt(&mut client, frame, now);
    let err = server.recv_packet(&wire, now).unwrap_err();
    assert_eq!(err, ConnError::FlowControl);
}

#[test]
fn stream_data_within_window_is_accepted() {
    let (mut server, mut client) = handshake_pair_with_credit(1 << 20, 1 << 20);
    let now = Instant::now();
    let frame = Frame::Stream {
        stream_id: 0,
        offset: 0,
        fin: false,
        length_prefixed: true,
        data: vec![7u8; 1000],
    };
    let wire = forge_one_rtt(&mut client, frame, now);
    server.recv_packet(&wire, now).expect("within window ok");
    let mut got = Vec::new();
    let n = server.stream_recv(0, &mut got);
    assert_eq!(n, 1000);
}

#[test]
fn reset_stream_final_size_over_window_is_flow_control_error() {
    let (mut server, mut client) = handshake_pair_with_credit(8, 1 << 30);
    let now = Instant::now();
    let frame = Frame::ResetStream {
        stream_id: 0,
        error_code: 0,
        final_size: 1_000_000,
    };
    let wire = forge_one_rtt(&mut client, frame, now);
    let err = server.recv_packet(&wire, now).unwrap_err();
    assert_eq!(err, ConnError::FlowControl);
}

#[test]
fn ack_with_huge_range_count_does_not_overallocate() {
    let mut buf = vec![dope_quic::frame::TYPE_ACK];
    dope_quic::varint::VarInt::encode(10, &mut buf).unwrap();
    dope_quic::varint::VarInt::encode(0, &mut buf).unwrap();
    dope_quic::varint::VarInt::encode(u32::MAX as u64, &mut buf).unwrap();
    dope_quic::varint::VarInt::encode(0, &mut buf).unwrap();
    let err = Frame::decode(&buf).unwrap_err();
    assert_eq!(err, dope_quic::frame::FrameError::Underflow);
}

fn forge_one_rtt(from: &mut Conn, frame: Frame, now: Instant) -> Vec<u8> {
    from.flush_test_one_rtt(frame, now)
}

#[test]
fn crypto_message_larger_than_cap_is_rejected() {
    let initial_dcid: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
    let client_scid: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let cfg = ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            initial_max_data: 1 << 20,
            ..transport_params::Params::default()
        },
        ..Default::default()
    };
    let mut server = Conn::new_server(
        initial_dcid.to_vec(),
        HS_CID.to_vec(),
        client_scid.to_vec(),
        signing,
        cfg,
    );

    let mut crypto_payload = vec![0x0b, 0xff, 0xff, 0xff];
    crypto_payload.extend_from_slice(&[0u8; 8]);
    let wire = build_client_initial(&initial_dcid, &client_scid, 0, &crypto_payload);
    let now = Instant::now();
    let err = server.recv_packet(&wire, now).unwrap_err();
    assert_eq!(err, ConnError::CryptoBufferExceeded);
}

fn build_client_initial(
    initial_dcid: &[u8],
    client_scid: &[u8],
    pn: u64,
    crypto_payload: &[u8],
) -> Vec<u8> {
    const TARGET_LEN: usize = 1200;
    const TAG_LEN: usize = 16;
    let secrets = InitialSecrets::from_dcid(initial_dcid);
    let prot = PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client));
    let mut frames_buf = Vec::new();
    Frame::Crypto {
        offset: 0,
        data: crypto_payload.to_vec(),
    }
    .encode(&mut frames_buf);
    let pn_len = 4u8;
    let mut payload = frames_buf;
    let header_len_estimate = 1 + 4 + 1 + initial_dcid.len() + 1 + client_scid.len() + 1 + 2;
    let needed_payload = TARGET_LEN.saturating_sub(header_len_estimate + pn_len as usize + TAG_LEN);
    if payload.len() < needed_payload {
        payload.resize(needed_payload, 0);
    }
    let body_len_after_pn = payload.len() + TAG_LEN;
    let h = InitialHeader {
        version: QUIC_V1,
        dcid: initial_dcid.to_vec(),
        scid: client_scid.to_vec(),
        token: vec![],
        packet_number: pn,
        pn_len,
    };
    let (header_bytes, pn_offset) = h.encode_with_pn(body_len_after_pn);
    prot.encrypt_long(&header_bytes, &payload, pn, pn_offset, pn_len as usize)
}
