pub mod support;

use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::conn::Error;
use dope_quic::packet::{InitialHeader, QUIC_V1, RetryPacket};
use dope_quic::{Connection, Handler, Mux, conn};

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

    let derived = RetryPacket::compute_tag(&odcid, &header).unwrap();
    assert_eq!(derived, tag, "RFC 9001 A.4 integrity tag mismatch");
}

struct NoopHandler;
impl Handler for NoopHandler {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: dope_quic::conn::Handle) {}
}

fn server_mux_with_retry(retry_secret: [u8; 32]) -> Mux<NoopHandler> {
    let signing = support::signing_key(0x39);
    let cfg = conn::Config {
        require_address_validation: true,
        retry_token_secret: Some(retry_secret),
        ..Default::default()
    };
    Mux::server(NoopHandler, signing, cfg).unwrap()
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
    let (mut wire, _) = h.encode_with_pn(100).unwrap();
    wire.resize(wire.len() + 100, 0);
    wire
}

#[test]
fn first_initial_without_token_triggers_retry() {
    let secret = [0xA1u8; 32];
    let mut mux = server_mux_with_retry(secret);

    let client_dcid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let client_scid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x99];
    let mut initial = craft_initial(&client_dcid, &client_scid, &[]);

    let from: SocketAddr = "127.0.0.1:55001".parse().unwrap();
    mux.recv(from, &mut initial, Instant::now()).unwrap();

    let outgoing: Vec<_> = mux.drain_outgoing().collect();
    assert_eq!(outgoing.len(), 1, "exactly one Retry should be emitted");
    let (dst, retry_wire) = (outgoing[0].addr(), outgoing[0].payload());
    assert_eq!(dst, from);
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

    let mut first_initial = craft_initial(&client_dcid, &client_scid, &[]);
    mux.recv(from, &mut first_initial, Instant::now()).unwrap();
    let first_out: Vec<_> = mux.drain_outgoing().collect();
    let retry = RetryPacket::decode(first_out[0].payload()).unwrap();
    let token = retry.token.clone();
    let new_dcid = retry.scid;

    let mut second_initial = craft_initial(&new_dcid, &client_scid, &token);
    let _ = mux.recv(from, &mut second_initial, Instant::now());
    let second_out: Vec<_> = mux.drain_outgoing().collect();
    for out in &second_out {
        let wire = out.payload();
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

    let mut first_initial = craft_initial(&client_dcid, &client_scid, &[]);
    mux.recv(from_a, &mut first_initial, Instant::now())
        .unwrap();
    let retry = RetryPacket::decode(mux.drain_outgoing().next().unwrap().payload()).unwrap();
    let token = retry.token;
    let new_dcid = retry.scid;

    let mut second_initial = craft_initial(&new_dcid, &client_scid, &token);
    let _ = mux.recv(from_b, &mut second_initial, Instant::now());
    let out: Vec<_> = mux.drain_outgoing().collect();
    assert!(
        out.is_empty(),
        "address-bound token mismatch must drop the packet silently"
    );
}

#[test]
fn retry_off_by_default_lets_initials_through() {
    let signing = support::signing_key(0x39);
    let mut mux = Mux::server(NoopHandler, signing, conn::Config::default()).unwrap();

    let mut initial = craft_initial(&[0u8; 8], &[1u8; 8], &[]);
    let from: SocketAddr = "127.0.0.1:55005".parse().unwrap();
    let _ = mux.recv(from, &mut initial, Instant::now());
    let out: Vec<_> = mux.drain_outgoing().collect();
    for o in &out {
        let wire = o.payload();
        let is_retry = matches!(wire.first(), Some(b) if b & 0xF0 == 0xF0);
        assert!(!is_retry, "off-by-default: no Retry should be emitted");
    }
}

const CLIENT_LOCAL_CID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

fn client_with_initial_dcid(initial_dcid: &[u8]) -> Connection {
    Connection::new_client(
        initial_dcid.to_vec(),
        CLIENT_LOCAL_CID.to_vec(),
        [0xABu8; 32],
        conn::Config::default(),
    )
    .unwrap()
}

fn craft_retry_for(odcid: &[u8], echo_dcid: &[u8], new_scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut retry = RetryPacket {
        version: QUIC_V1,
        dcid: echo_dcid.to_vec(),
        scid: new_scid.to_vec(),
        token: token.to_vec(),
        integrity_tag: [0u8; 16],
    };
    retry.integrity_tag = retry.compute_integrity_tag(odcid).unwrap();
    retry.encode().unwrap()
}

#[test]
fn client_accepts_retry_and_resends_initial_with_token() {
    let original_dcid = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let mut client = client_with_initial_dcid(&original_dcid);

    let first = client.send_packets(Instant::now());
    assert!(!first.is_empty(), "client must emit its first Initial");

    let new_scid = vec![0xF0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
    let token = b"server-issued-retry-token".to_vec();
    let mut retry_wire = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &new_scid, &token);

    client
        .recv_packet(&mut retry_wire, Instant::now())
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

    client.recv_packet(&mut wire, Instant::now()).expect("recv");

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

    let mut retry_a = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &scid_a, &token_a);
    client.recv_packet(&mut retry_a, Instant::now()).unwrap();

    let mut retry_b = craft_retry_for(&original_dcid, &CLIENT_LOCAL_CID, &scid_b, &token_b);
    client.recv_packet(&mut retry_b, Instant::now()).unwrap();

    let next = client.send_packets(Instant::now());
    let prefix = InitialHeader::decode_pre_hp(&next[0]).expect("decode");
    assert_eq!(
        prefix.dcid, scid_a,
        "first Retry's scid must remain in effect"
    );
    assert_eq!(prefix.token, token_a, "first Retry's token must remain");
}

#[test]
fn retry_token_that_cannot_fit_active_initial_ceiling_closes_without_panic() {
    let original_dcid = vec![0xceu8; 8];
    let config = conn::Config {
        max_pmtu: 1200,
        ..Default::default()
    };
    let mut client = Connection::new_client(
        original_dcid.clone(),
        CLIENT_LOCAL_CID.to_vec(),
        [0xabu8; 32],
        config,
    )
    .unwrap();
    assert_eq!(client.send_packets(Instant::now()).len(), 1);

    let mut retry = craft_retry_for(
        &original_dcid,
        &CLIENT_LOCAL_CID,
        &[0x44; 8],
        &vec![0x91; 1200],
    );
    assert_eq!(
        client.recv_packet(&mut retry, Instant::now()),
        Err(Error::PacketCeiling)
    );
    assert!(client.is_closed());
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
