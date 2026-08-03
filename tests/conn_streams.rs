pub mod support;

use std::time::{Duration, Instant};

use dope_quic::SendBuffer;
use dope_quic::conn::stream::{Error, Event};
use o3::buffer::{Bytes, Retained, Shared};

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
        Some(Event::Data {
            stream_id: client_stream
        })
    );
    assert_eq!(
        server.poll_stream_event(),
        Some(Event::Finished {
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
fn drained_stream_can_be_rescheduled_before_stale_ticket_cleanup() {
    let (mut server, mut client) = support::connected_pair();
    let stream = client.open_bidi_stream().unwrap();
    let now = Instant::now();

    client.stream_send(stream, b"first").unwrap();
    support::transfer(&mut client, &mut server, now);
    client.stream_send(stream, b"second").unwrap();
    support::transfer(&mut client, &mut server, now);

    assert_eq!(
        server.stream_recv_owned(stream).as_deref(),
        Some(&b"firstsecond"[..])
    );
}

#[test]
fn fin_only_stream_is_not_blocked_by_zero_byte_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(0, 0, 1, 0),
        support::config_with_credit(0, 0, 1, 0),
    );
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send_fin(stream).unwrap();

    support::transfer(&mut client, &mut server, Instant::now());

    assert_eq!(
        server.poll_stream_event(),
        Some(Event::Finished { stream_id: stream })
    );
    assert!(server.stream_recv_eof(stream));
}

#[test]
fn lost_fin_only_stream_is_retransmitted() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(0, 0, 1, 0),
        support::config_with_credit(0, 0, 1, 0),
    );
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send_fin(stream).unwrap();
    let now = Instant::now();
    assert!(!client.send_packets(now).is_empty());

    let timeout = client.next_timer().unwrap() + Duration::from_millis(1);
    client.check_loss(timeout);
    support::transfer(&mut client, &mut server, timeout);

    assert_eq!(
        server.poll_stream_event(),
        Some(Event::Finished { stream_id: stream })
    );
}

#[test]
fn multiple_connection_blocked_streams_share_one_control_delivery() {
    let (_server, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 0, 8, 8),
        support::config(),
    );
    for _ in 0..2 {
        let stream = client.open_bidi_stream().unwrap();
        client.stream_send(stream, b"blocked").unwrap();
    }

    assert!(!client.send_packets(Instant::now()).is_empty());
    assert!(client.is_established());
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
fn inline_and_retained_segments_cross_as_one_stream() {
    let (mut server, mut client) = support::connected_pair();
    let stream = server.open_bidi_stream().unwrap();
    server
        .stream_send_buffer(stream, SendBuffer::inline(b"frame-").unwrap())
        .unwrap();
    server
        .stream_send_buffer(
            stream,
            SendBuffer::Retained(Bytes::<Retained>::from(Shared::from_static(b"body"))),
        )
        .unwrap();
    server.stream_send_fin(stream).unwrap();

    support::transfer(&mut server, &mut client, Instant::now());

    assert_eq!(
        client.stream_recv_owned(stream).as_deref(),
        Some(&b"frame-body"[..])
    );
    assert!(client.stream_recv_eof(stream));
}

#[test]
fn retired_receive_half_keeps_bidirectional_send_half_open() {
    let (mut server, mut client) = support::connected_pair();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, b"request").unwrap();
    client.stream_send_fin(stream).unwrap();

    let now = Instant::now();
    support::transfer(&mut client, &mut server, now);
    assert_eq!(
        server.stream_recv_owned(stream).as_deref(),
        Some(&b"request"[..])
    );
    assert!(server.stream_recv_eof(stream));

    server.stream_send(stream, b"response").unwrap();
    server.stream_send_fin(stream).unwrap();
    support::transfer(&mut server, &mut client, now);
    assert_eq!(
        client.stream_recv_owned(stream).as_deref(),
        Some(&b"response"[..])
    );
    assert!(client.stream_recv_eof(stream));
}

#[test]
fn stop_sending_returns_a_reset_with_the_same_error() {
    let (mut server, mut client) = support::connected_pair();
    let stream = server.open_bidi_stream().unwrap();
    server.stream_send(stream, b"unwanted").unwrap();
    let now = Instant::now();
    support::transfer(&mut server, &mut client, now);
    assert_eq!(
        client.poll_stream_event(),
        Some(Event::Data { stream_id: stream })
    );
    client.stream_stop_sending(stream, 0x99).unwrap();
    support::transfer(&mut client, &mut server, now);
    assert_eq!(server.stream_send_stopped(stream), Some(0x99));
    support::transfer(&mut server, &mut client, now);
    assert_eq!(
        client.poll_stream_event(),
        Some(Event::Reset {
            stream_id: stream,
            error_code: 0x99,
        })
    );
    assert!(client.stream_recv_eof(stream));
}

#[test]
fn peer_stream_limits_are_enforced_by_the_allocator() {
    let (_, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
    );
    assert_eq!(client.open_bidi_stream(), Ok(0));
    assert_eq!(client.open_bidi_stream(), Err(Error::PeerLimit));
    assert_eq!(client.open_uni_stream(), Err(Error::PeerLimit));
}

#[test]
fn closed_bidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 2, 0),
        support::config_with_credit(1 << 20, 1 << 20, 2, 0),
    );
    let streams = [
        client.open_bidi_stream().unwrap(),
        client.open_bidi_stream().unwrap(),
    ];
    assert_eq!(client.open_bidi_stream(), Err(Error::PeerLimit));

    let now = Instant::now();
    for stream in streams {
        client.stream_send(stream, b"request").unwrap();
        client.stream_send_fin(stream).unwrap();
    }
    support::transfer(&mut client, &mut server, now);
    for stream in streams {
        assert_eq!(
            server.stream_recv_owned(stream).as_deref(),
            Some(&b"request"[..]),
        );
        server.stream_send(stream, b"response").unwrap();
        server.stream_send_fin(stream).unwrap();
    }
    support::transfer(&mut server, &mut client, now);
    for round in 1..=4 {
        let at = now + Duration::from_millis(round * 20);
        support::transfer(&mut client, &mut server, at);
        support::transfer(&mut server, &mut client, at);
    }

    assert_eq!(client.open_bidi_stream(), Ok(8));
}

#[test]
fn consumed_unidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 0, 2),
        support::config_with_credit(1 << 20, 1 << 20, 0, 2),
    );
    let streams = [
        client.open_uni_stream().unwrap(),
        client.open_uni_stream().unwrap(),
    ];
    assert_eq!(client.open_uni_stream(), Err(Error::PeerLimit));

    let now = Instant::now();
    for stream in streams {
        client.stream_send(stream, b"one-way").unwrap();
        client.stream_send_fin(stream).unwrap();
    }
    support::transfer(&mut client, &mut server, now);
    for stream in streams {
        assert_eq!(
            server.stream_recv_owned(stream).as_deref(),
            Some(&b"one-way"[..]),
        );
    }
    support::transfer(&mut server, &mut client, now);

    assert_eq!(client.open_uni_stream(), Ok(10));
}

#[test]
fn reset_unidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 0, 1),
        support::config_with_credit(1 << 20, 1 << 20, 0, 1),
    );
    let stream = client.open_uni_stream().unwrap();
    assert_eq!(client.open_uni_stream(), Err(Error::PeerLimit));

    client.stream_reset(stream, 0x42).unwrap();
    let now = Instant::now();
    support::transfer(&mut client, &mut server, now);
    assert_eq!(
        server.poll_stream_event(),
        Some(Event::Reset {
            stream_id: stream,
            error_code: 0x42,
        })
    );
    support::transfer(&mut server, &mut client, now);

    assert!(client.open_uni_stream().is_ok());
}
