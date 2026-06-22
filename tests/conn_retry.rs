use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::packet::{InitialHeader, QUIC_V1, RetryPacket};
use dope_quic::{Conn, ConnConfig, Handler, Mux};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

#[test]
fn retry_round_trip_decode_matches_encode() {
    let odcid = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let mut retry = RetryPacket {
        version: QUIC_V1,
        dcid: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
        scid: vec![0xF0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5],
        token: b"my-opaque-token-bytes".to_vec(),
        integrity_tag: [0u8; 16],
    };
    retry.integrity_tag = retry.compute_integrity_tag(&odcid);
    let wire = retry.encode();

    let decoded = RetryPacket::decode(&wire).expect("decode retry");
    assert_eq!(decoded, retry);
    assert!(
        decoded.verify_integrity(&odcid),
        "tag must verify with the same ODCID",
    );
}

#[test]
fn retry_integrity_rejects_wrong_odcid() {
    let real_odcid = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let bogus_odcid = vec![9, 9, 9, 9, 9, 9, 9, 9];
    let mut retry = RetryPacket {
        version: QUIC_V1,
        dcid: vec![0; 8],
        scid: vec![1; 8],
        token: vec![],
        integrity_tag: [0u8; 16],
    };
    retry.integrity_tag = retry.compute_integrity_tag(&real_odcid);
    let wire = retry.encode();
    let decoded = RetryPacket::decode(&wire).unwrap();
    assert!(decoded.verify_integrity(&real_odcid));
    assert!(!decoded.verify_integrity(&bogus_odcid));
}

#[test]
fn retry_integrity_rejects_tampered_token() {
    let odcid = vec![0xAB; 8];
    let mut retry = RetryPacket {
        version: QUIC_V1,
        dcid: vec![0; 8],
        scid: vec![1; 8],
        token: b"original-token".to_vec(),
        integrity_tag: [0u8; 16],
    };
    retry.integrity_tag = retry.compute_integrity_tag(&odcid);
    let wire = retry.encode();
    let mut decoded = RetryPacket::decode(&wire).unwrap();
    decoded.token[0] ^= 0x01;
    assert!(!decoded.verify_integrity(&odcid));
}

#[test]
fn retry_decode_rejects_short_packet() {
    let too_short = vec![0xF0u8; 22];
    assert!(RetryPacket::decode(&too_short).is_err());
}

#[test]
fn retry_decode_rejects_wrong_long_type() {
    let mut wire = vec![0u8; 30];
    wire[0] = 0xC0;
    wire[1..5].copy_from_slice(&QUIC_V1.to_be_bytes());
    assert!(RetryPacket::decode(&wire).is_err());
}

#[test]
fn rfc9001_a4_vector_round_trips() {
    let odcid = hex_decode("8394c8f03e515708");
    let header = hex_decode(
        "ff000000010008f067a5502a4262b574\
         6f6b656e",
    );
    let expected_tag = hex_decode("04a265ba2eff4d829058fb3f0f2496ba");

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&expected_tag);

    let derived = RetryPacket::compute_tag(&odcid, &header);
    assert_eq!(derived, tag, "RFC 9001 A.4 integrity tag mismatch");
}

struct NoopHandler;
impl Handler for NoopHandler {
    fn on_established(&mut self, _conn: &mut Conn, _h: dope_quic::ConnHandle) {}
    fn on_datagram(&mut self, _conn: &mut Conn, _h: dope_quic::ConnHandle, _data: Vec<u8>) {}
    fn on_close(&mut self, _h: dope_quic::ConnHandle) {}
}

fn server_mux_with_retry(retry_secret: [u8; 32]) -> Mux<NoopHandler> {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let cfg = ConnConfig {
        require_address_validation: true,
        retry_token_secret: Some(retry_secret),
        ..Default::default()
    };
    Mux::server(NoopHandler, signing, cfg)
}

fn craft_initial(dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    use dope_quic::packet::{InitialHeader, QUIC_V1};
    let h = InitialHeader {
        version: QUIC_V1,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: token.to_vec(),
        packet_number: 0,
        pn_len: 1,
    };
    let (mut wire, _) = h.encode_with_pn(100);
    wire.resize(wire.len() + 100, 0);
    wire
}

#[test]
fn first_initial_without_token_triggers_retry() {
    let secret = [0xA1u8; 32];
    let mut mux = server_mux_with_retry(secret);

    let client_dcid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let client_scid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x99];
    let initial = craft_initial(&client_dcid, &client_scid, &[]);

    let from: SocketAddr = "127.0.0.1:55001".parse().unwrap();
    mux.on_udp_packet(from, &initial, Instant::now()).unwrap();

    let outgoing = mux.pull_outgoing();
    assert_eq!(outgoing.len(), 1, "exactly one Retry should be emitted");
    let (dst, retry_wire) = &outgoing[0];
    assert_eq!(*dst, from);
    let retry = RetryPacket::decode(retry_wire).expect("decode Retry");
    assert_eq!(retry.dcid, client_scid, "retry DCID echoes client's SCID");
    assert!(
        retry.verify_integrity(&client_dcid),
        "tag must verify with the original DCID",
    );
    assert!(!retry.token.is_empty(), "retry must carry a server token");
}

#[test]
fn second_initial_with_valid_token_does_not_re_retry() {
    let secret = [0xA2u8; 32];
    let mut mux = server_mux_with_retry(secret);

    let client_dcid = [0x77u8; 8];
    let client_scid = [0x44u8; 8];
    let from: SocketAddr = "127.0.0.1:55002".parse().unwrap();

    mux.on_udp_packet(
        from,
        &craft_initial(&client_dcid, &client_scid, &[]),
        Instant::now(),
    )
    .unwrap();
    let first_out = mux.pull_outgoing();
    let retry = RetryPacket::decode(&first_out[0].1).unwrap();
    let token = retry.token.clone();
    let new_dcid = retry.scid;

    let _ = mux.on_udp_packet(
        from,
        &craft_initial(&new_dcid, &client_scid, &token),
        Instant::now(),
    );
    let second_out = mux.pull_outgoing();
    for (_addr, wire) in &second_out {
        let is_retry = matches!(wire.first(), Some(b) if b & 0xF0 == 0xF0);
        assert!(
            !is_retry,
            "second Initial with token must not produce another Retry"
        );
    }
}

#[test]
fn second_initial_with_wrong_addr_is_rejected() {
    let secret = [0xA3u8; 32];
    let mut mux = server_mux_with_retry(secret);

    let client_dcid = [0x88u8; 8];
    let client_scid = [0x99u8; 8];
    let from_a: SocketAddr = "127.0.0.1:55003".parse().unwrap();
    let from_b: SocketAddr = "127.0.0.1:55004".parse().unwrap();

    mux.on_udp_packet(
        from_a,
        &craft_initial(&client_dcid, &client_scid, &[]),
        Instant::now(),
    )
    .unwrap();
    let retry = RetryPacket::decode(&mux.pull_outgoing()[0].1).unwrap();
    let token = retry.token;
    let new_dcid = retry.scid;

    let _ = mux.on_udp_packet(
        from_b,
        &craft_initial(&new_dcid, &client_scid, &token),
        Instant::now(),
    );
    let out = mux.pull_outgoing();
    assert!(
        out.is_empty(),
        "address-bound token mismatch must drop the packet silently"
    );
}

#[test]
fn retry_off_by_default_lets_initials_through() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let mut mux = Mux::server(NoopHandler, signing, ConnConfig::default());

    let initial = craft_initial(&[0u8; 8], &[1u8; 8], &[]);
    let from: SocketAddr = "127.0.0.1:55005".parse().unwrap();
    let _ = mux.on_udp_packet(from, &initial, Instant::now());
    let out = mux.pull_outgoing();
    for (_addr, wire) in &out {
        let is_retry = matches!(wire.first(), Some(b) if b & 0xF0 == 0xF0);
        assert!(!is_retry, "off-by-default: no Retry should be emitted");
    }
}

const CLIENT_LOCAL_CID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

fn client_with_initial_dcid(initial_dcid: &[u8]) -> Conn {
    Conn::new_client(
        initial_dcid.to_vec(),
        CLIENT_LOCAL_CID.to_vec(),
        [0xABu8; 32],
        ConnConfig::default(),
    )
}

fn craft_retry_for(odcid: &[u8], echo_dcid: &[u8], new_scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut retry = RetryPacket {
        version: QUIC_V1,
        dcid: echo_dcid.to_vec(),
        scid: new_scid.to_vec(),
        token: token.to_vec(),
        integrity_tag: [0u8; 16],
    };
    retry.integrity_tag = retry.compute_integrity_tag(odcid);
    retry.encode()
}

#[test]
fn client_accepts_retry_and_resends_initial_with_token() {
    let original_dcid = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let mut client = client_with_initial_dcid(&original_dcid);

    let first = client.send_packets(Instant::now());
    assert!(!first.is_empty(), "client must emit its first Initial");

    let new_scid = vec![0xF0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
    let token = b"server-issued-retry-token".to_vec();
    let retry_wire = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &new_scid, &token);

    client
        .recv_packet(&retry_wire, Instant::now())
        .expect("recv retry");

    let second = client.send_packets(Instant::now());
    assert!(!second.is_empty(), "client must resend Initial after Retry");
    let prefix = InitialHeader::decode_pre_hp(&second[0]).expect("decode reissued initial");
    assert_eq!(prefix.dcid, new_scid, "client must swap DCID to retry.scid");
    assert_eq!(prefix.token, token, "client must attach the retry token");
    assert_eq!(
        prefix.scid,
        CLIENT_LOCAL_CID.to_vec(),
        "client SCID is preserved"
    );
}

#[test]
fn client_drops_retry_with_invalid_integrity() {
    let original_dcid = vec![0xAAu8; 8];
    let mut client = client_with_initial_dcid(&original_dcid);
    let _ = client.send_packets(Instant::now());

    let new_scid = vec![0x55u8; 8];
    let token = b"tok".to_vec();
    let mut wire = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &new_scid, &token);
    let n = wire.len();
    wire[n - 1] ^= 0xFF;

    client.recv_packet(&wire, Instant::now()).expect("recv");

    let next = client.send_packets(Instant::now());
    for w in &next {
        let prefix = InitialHeader::decode_pre_hp(w).expect("decode");
        assert_ne!(prefix.dcid, new_scid, "rejected Retry must not swap DCID");
        assert!(
            prefix.token.is_empty(),
            "rejected Retry must not attach token"
        );
    }
}

#[test]
fn client_ignores_second_retry() {
    let original_dcid = vec![0xCCu8; 8];
    let mut client = client_with_initial_dcid(&original_dcid);
    let _ = client.send_packets(Instant::now());

    let scid_a = vec![0x10u8; 8];
    let scid_b = vec![0x20u8; 8];
    let token_a = b"first-token".to_vec();
    let token_b = b"second-token".to_vec();

    let retry_a = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &scid_a, &token_a);
    client.recv_packet(&retry_a, Instant::now()).unwrap();

    let retry_b = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &scid_b, &token_b);
    client.recv_packet(&retry_b, Instant::now()).unwrap();

    let next = client.send_packets(Instant::now());
    let prefix = InitialHeader::decode_pre_hp(&next[0]).expect("decode");
    assert_eq!(
        prefix.dcid, scid_a,
        "first Retry's scid must remain in effect"
    );
    assert_eq!(prefix.token, token_a, "first Retry's token must remain");
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
