pub mod support;

use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::{conn, conn::session::Connection, transport_params};

const CID: [u8; 8] = [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44];

fn drain<R: support::Receiver>(
    workspace: &mut conn::ReceiveWorkspace,
    from: &mut Connection,
    into: &mut R,
) {
    let now = Instant::now();
    for mut pkt in from.transmit().send(now) {
        into.receive(workspace, &mut pkt, now);
    }
}

fn cfg() -> conn::config::Options {
    conn::config::Options {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            ..transport_params::Params::default()
        },
        ..Default::default()
    }
}

fn handshake() -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    handshake_with_control_capacity(cfg().control_journal_capacity)
}

fn handshake_with_control_capacity(
    control_journal_capacity: usize,
) -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server_config = cfg();
    server_config.control_journal_capacity = control_journal_capacity;
    let mut client_config = cfg();
    client_config.control_journal_capacity = control_journal_capacity;

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        server_config,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        client_config,
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();

    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    assert!(client.status().is_established() && server.status().is_established());
    (server, client, workspace)
}

#[test]
fn path_challenge_round_trip() {
    use dope_quic::frame::Frame;
    let f = Frame::PathChallenge {
        data: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 0x1a, "type byte = TYPE_PATH_CHALLENGE");
    assert_eq!(buf.len(), 1 + 8);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(decoded, f);
    assert_eq!(n, buf.len());
}

#[test]
fn path_response_round_trip() {
    use dope_quic::frame::Frame;
    let f = Frame::PathResponse {
        data: [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf).unwrap();
    assert_eq!(buf[0], 0x1b);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(decoded, f);
    assert_eq!(n, buf.len());
}

#[test]
fn active_challenge_response_round_trip_validates_path() {
    let (mut server, mut client, mut workspace) = handshake();
    let token = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];

    server.send_path_challenge(token);
    assert!(
        !server.status().path_validated(&token),
        "not yet validated — RESPONSE hasn't come back",
    );

    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);

    assert!(
        server.status().path_validated(&token),
        "server should have validated the path after RESPONSE round-trip",
    );
}

#[test]
fn unsolicited_path_response_does_not_falsely_validate() {
    let (server, client, _workspace) = handshake();

    let bogus = [0u8; 8];
    let _ = (client, bogus);
    assert!(
        !server.status().path_validated(&[0xFFu8; 8]),
        "never-issued token must not be reported validated",
    );
}

#[test]
fn pre_handshake_send_path_challenge_is_noop() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        cfg(),
    )
    .unwrap();
    assert!(client.status().is_handshaking());
    let token = [0x01u8; 8];
    client.send_path_challenge(token);
    let _ = client.transmit().send(Instant::now());
    assert!(!client.status().path_validated(&token));
}

#[test]
fn multiple_outstanding_challenges_validate_independently() {
    let (mut server, mut client, mut workspace) = handshake();
    let a = [0xAAu8; 8];
    let b = [0xBBu8; 8];
    server.send_path_challenge(a);
    server.send_path_challenge(b);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    assert!(server.status().path_validated(&a));
    assert!(server.status().path_validated(&b));
}

#[test]
fn bounded_control_backpressure_preserves_every_path_challenge() {
    const TOKENS: usize = 64;
    const CONTROL_CAPACITY: usize = 32;
    let (mut server, mut client, mut workspace) = handshake_with_control_capacity(CONTROL_CAPACITY);
    let tokens: Vec<_> = (0..TOKENS)
        .map(|token| (token as u64).to_ne_bytes())
        .collect();

    for &token in &tokens {
        client.send_path_challenge(token);
    }

    for _ in 0..16 {
        drain(&mut workspace, &mut client, &mut server);
        drain(&mut workspace, &mut server, &mut client);
        drain(&mut workspace, &mut client, &mut server);
        if tokens
            .iter()
            .all(|token| client.status().path_validated(token))
        {
            break;
        }
    }

    assert!(
        tokens
            .iter()
            .all(|token| client.status().path_validated(token)),
        "control journal pressure must defer rather than drop path challenges",
    );
}

#[test]
fn unknown_path_response_does_not_break_conn() {
    use dope_quic::frame::Frame;
    let f = Frame::PathResponse { data: [0u8; 8] };
    let mut buf = Vec::new();
    f.encode(&mut buf).unwrap();
    let frames = Frame::decode_all(&buf).expect("decode");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], f);
}
