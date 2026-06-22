use std::time::Instant;

use dope_quic::{Conn, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn drain(from: &mut Conn, into: &mut Conn) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

fn user_tp() -> dope_quic::ConnConfig {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

#[test]
fn handshake_acks_drain_initial_and_handshake_spaces() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey();

    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    drain(&mut client, &mut server);
    assert_eq!(client.unacked_count(0), 1, "client Initial inflight");

    drain(&mut server, &mut client);
    assert_eq!(client.unacked_count(0), 0, "client Initial acked");
    assert_eq!(server.unacked_count(0), 0, "server Initial discarded");
    assert_eq!(server.unacked_count(1), 1, "server Handshake inflight");

    drain(&mut client, &mut server);
    assert!(client.is_established());
    assert!(server.is_established());
    assert_eq!(server.unacked_count(1), 0, "server Handshake acked");
    assert_eq!(client.unacked_count(0), 0, "client Initial discarded");
    assert_eq!(client.unacked_count(1), 1, "client Handshake (CF) inflight");

    drain(&mut server, &mut client);
    assert_eq!(server.unacked_count(1), 0, "server Handshake discarded");
    assert!(client.handshake_confirmed(), "client saw HANDSHAKE_DONE");
    assert_eq!(client.unacked_count(1), 0, "client Handshake discarded");
}
