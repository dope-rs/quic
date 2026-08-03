pub mod support;

use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::{Connection, conn, transport_params};

const CID: [u8; 8] = [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33];

fn drain<R: support::Receiver>(from: &mut Connection, into: &mut R) {
    let now = Instant::now();
    for mut pkt in from.send_packets(now) {
        into.receive(&mut pkt, now);
    }
}

fn cfg(cid_prefix: Option<u8>) -> conn::Config {
    conn::Config {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            ..transport_params::Params::default()
        },
        cid_prefix,
        ..Default::default()
    }
}

fn make_pair(
    server_prefix: Option<u8>,
    client_prefix: Option<u8>,
) -> (server::Connection, Connection) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Connection::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        cfg(server_prefix),
    )
    .unwrap();
    let mut client = Connection::new_client(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        cfg(client_prefix),
    )
    .unwrap();

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    (server, client)
}

fn issued_cids(conn: &Connection) -> Vec<&Vec<u8>> {
    conn.local_cids()
        .iter()
        .filter(|(seq, _)| **seq > 0)
        .map(|(_, c)| c)
        .collect()
}

#[test]
fn prefixed_cids_all_start_with_tag_byte() {
    const TAG: u8 = 0x77;
    let (server, _client) = make_pair(Some(TAG), None);
    let cids: Vec<&Vec<u8>> = server.local_cids().values().collect();
    assert!(cids.len() >= 2, "expected ≥2 CIDs after handshake");
    let issued = issued_cids(&server);
    assert!(!issued.is_empty(), "no auto-issued CIDs found");
    for cid in &issued {
        assert_eq!(
            cid[0], TAG,
            "issued CID byte 0 must carry tag; got {:02x?}",
            cid
        );
    }
}

#[test]
fn client_side_cid_prefix_is_honored() {
    const TAG: u8 = 0xAB;
    let (_server, client) = make_pair(None, Some(TAG));
    let issued = issued_cids(&client);
    assert!(!issued.is_empty(), "client must issue ≥1 NEW_CONNECTION_ID");
    for cid in &issued {
        assert_eq!(
            cid[0], TAG,
            "client-issued CID byte 0 must carry client tag; got {:02x?}",
            cid,
        );
    }
}

#[test]
fn distinct_prefixes_separate_cleanly() {
    const TAG_A: u8 = 0x01;
    const TAG_B: u8 = 0x02;
    let (server_a, _) = make_pair(Some(TAG_A), None);
    let (server_b, _) = make_pair(Some(TAG_B), None);

    let issued_a: Vec<&Vec<u8>> = issued_cids(&server_a);
    let issued_b: Vec<&Vec<u8>> = issued_cids(&server_b);
    assert!(!issued_a.is_empty() && !issued_b.is_empty());

    for cid in &issued_a {
        assert_eq!(cid[0], TAG_A);
    }
    for cid in &issued_b {
        assert_eq!(cid[0], TAG_B);
    }
}

#[test]
fn prefix_does_not_break_uniqueness_of_remaining_bytes() {
    const TAG: u8 = 0xC0;
    let (server, _client) = make_pair(Some(TAG), None);
    let issued: Vec<Vec<u8>> = issued_cids(&server).into_iter().cloned().collect();
    assert!(
        issued.len() >= 2,
        "need ≥2 CIDs to compare; got {}",
        issued.len()
    );

    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for cid in &issued {
        assert!(cid.len() >= 2, "CID too short: {:02x?}", cid);
        assert!(
            seen.insert(&cid[1..]),
            "two issued CIDs collided after tag-stripping: {:02x?}",
            cid,
        );
    }
}
