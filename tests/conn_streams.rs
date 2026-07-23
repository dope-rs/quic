pub mod support;

use std::time::Instant;

use dope_quic::{StreamError, StreamEvent};

#[test]
fn bidirectional_data_fin_and_events_cross_the_connection() {
    let (mut server, mut client) = support::connected_pair();
    let client_stream = client.open_bidi_stream().unwrap();
    let server_stream = server.open_bidi_stream().unwrap();
    client.stream_send(client_stream, b"client").unwrap();
    client.stream_send_fin(client_stream).unwrap();
    server.stream_send(server_stream, b"server").unwrap();
    server.stream_send_fin(server_stream).unwrap();
    let now = Instant::now();
    support::transfer(&mut client, &mut server, now);
    support::transfer(&mut server, &mut client, now);

    assert_eq!(
        server.poll_stream_event(),
        Some(StreamEvent::Data {
            stream_id: client_stream
        })
    );
    assert_eq!(
        server.poll_stream_event(),
        Some(StreamEvent::Finished {
            stream_id: client_stream
        })
    );
    let mut from_client = Vec::new();
    let mut from_server = Vec::new();
    server.stream_recv(client_stream, &mut from_client);
    client.stream_recv(server_stream, &mut from_server);
    assert_eq!(from_client, b"client");
    assert_eq!(from_server, b"server");
    assert!(server.stream_recv_eof(client_stream));
    assert!(client.stream_recv_eof(server_stream));
}

#[test]
fn reading_releases_stream_flow_control_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(5, 1 << 20, 8, 8),
        support::config_with_credit(5, 1 << 20, 8, 8),
    );
    let stream = server.open_bidi_stream().unwrap();
    server.stream_send(stream, b"abcdefghij").unwrap();
    let now = Instant::now();
    support::transfer(&mut server, &mut client, now);
    let mut received = Vec::new();
    client.stream_recv(stream, &mut received);
    assert_eq!(received, b"abcde");

    support::transfer(&mut client, &mut server, now);
    support::transfer(&mut server, &mut client, now);
    received.clear();
    client.stream_recv(stream, &mut received);
    assert_eq!(received, b"fghij");
}

#[test]
fn owned_receive_moves_each_batch_and_releases_flow_control_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(5, 1 << 20, 8, 8),
        support::config_with_credit(5, 1 << 20, 8, 8),
    );
    let stream = server.open_bidi_stream().unwrap();
    server.stream_send(stream, b"abcdefghij").unwrap();
    let now = Instant::now();
    support::transfer(&mut server, &mut client, now);

    assert_eq!(
        client.stream_recv_owned(stream).as_deref(),
        Some(&b"abcde"[..])
    );
    assert!(client.stream_recv_owned(stream).is_none());

    support::transfer(&mut client, &mut server, now);
    support::transfer(&mut server, &mut client, now);
    assert_eq!(
        client.stream_recv_owned(stream).as_deref(),
        Some(&b"fghij"[..])
    );
}

#[test]
fn stop_sending_returns_a_reset_with_the_same_error() {
    let (mut server, mut client) = support::connected_pair();
    let stream = server.open_bidi_stream().unwrap();
    server.stream_send(stream, b"unwanted").unwrap();
    let now = Instant::now();
    support::transfer(&mut server, &mut client, now);
    client.stream_stop_sending(stream, 0x99).unwrap();
    support::transfer(&mut client, &mut server, now);
    assert_eq!(server.stream_send_stopped(stream), Some(0x99));
    support::transfer(&mut server, &mut client, now);
    assert_eq!(client.stream_recv_reset(stream), Some(0x99));
}

#[test]
fn peer_stream_limits_are_enforced_by_the_allocator() {
    let (_, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
    );
    assert_eq!(client.open_bidi_stream(), Ok(0));
    assert_eq!(client.open_bidi_stream(), Err(StreamError::PeerLimit));
    assert_eq!(client.open_uni_stream(), Err(StreamError::PeerLimit));
}
