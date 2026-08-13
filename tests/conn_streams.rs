pub mod support;

use std::time::{Duration, Instant};

use dope_quic::SendBuffer;
use dope_quic::conn::{
    self,
    stream::{Error, Event},
};
use o3::buffer::{
    bytes::{Bytes, Retained},
    storage::Shared,
};

#[test]
fn bidirectional_data_fin_and_events_cross_the_connection() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let client_stream = client.streams().open_bidi().unwrap();
    let server_stream = server.streams().open_bidi().unwrap();
    client.streams().send(client_stream, b"client").unwrap();
    client.streams().finish(client_stream).unwrap();
    server.streams().send(server_stream, b"server").unwrap();
    server.streams().finish(server_stream).unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    support::transfer(&mut workspace, &mut server, &mut client, now);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable {
            stream_id: client_stream
        })
    );
    assert_eq!(server.stream_events().poll_event(), None);
    let mut from_client = Vec::new();
    let mut from_server = Vec::new();
    server.streams().recv(client_stream, &mut from_client);
    client.streams().recv(server_stream, &mut from_server);
    assert_eq!(from_client, b"client");
    assert_eq!(from_server, b"server");
    assert!(server.stream_state().recv_eof(client_stream));
    assert!(client.stream_state().recv_eof(server_stream));
}

#[test]
fn drained_stream_can_be_rescheduled_before_stale_ticket_cleanup() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let stream = client.streams().open_bidi().unwrap();
    let now = Instant::now();

    client.streams().send(stream, b"first").unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    client.streams().send(stream, b"second").unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);

    assert_eq!(
        server.streams().recv_owned(stream).as_deref(),
        Some(&b"firstsecond"[..])
    );
}

#[test]
fn fin_only_stream_is_not_blocked_by_zero_byte_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(0, 0, 1, 0),
        support::config_with_credit(0, 0, 1, 0),
    );
    let stream = client.streams().open_bidi().unwrap();
    client.streams().finish(stream).unwrap();

    support::transfer(&mut workspace, &mut client, &mut server, Instant::now());

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );
    assert!(server.stream_state().recv_eof(stream));
}

#[test]
fn lost_fin_only_stream_is_retransmitted() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(0, 0, 1, 0),
        support::config_with_credit(0, 0, 1, 0),
    );
    let stream = client.streams().open_bidi().unwrap();
    client.streams().finish(stream).unwrap();
    let now = Instant::now();
    assert!(!client.transmit().send(now).is_empty());

    let timeout = client.status().next_timer().unwrap() + Duration::from_millis(1);
    conn::recovery::Loss::new(&mut client).check_loss(timeout);
    support::transfer(&mut workspace, &mut client, &mut server, timeout);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );
}

#[test]
fn multiple_connection_blocked_streams_share_one_control_delivery() {
    let (_server, mut client, _workspace) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 0, 8, 8),
        support::config(),
    );
    for _ in 0..2 {
        let stream = client.streams().open_bidi().unwrap();
        client.streams().send(stream, b"blocked").unwrap();
    }

    assert!(!client.transmit().send(Instant::now()).is_empty());
    assert!(client.status().is_established());
}

#[test]
fn reading_releases_stream_flow_control_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(5, 1 << 20, 8, 8),
        support::config_with_credit(5, 1 << 20, 8, 8),
    );
    let stream = server.streams().open_bidi().unwrap();
    server.streams().send(stream, b"abcdefghij").unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut server, &mut client, now);
    let mut received = Vec::new();
    client.streams().recv(stream, &mut received);
    assert_eq!(received, b"abcde");

    support::transfer(&mut workspace, &mut client, &mut server, now);
    support::transfer(&mut workspace, &mut server, &mut client, now);
    received.clear();
    client.streams().recv(stream, &mut received);
    assert_eq!(received, b"fghij");
}

#[test]
fn owned_receive_moves_each_batch_and_releases_flow_control_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(5, 1 << 20, 8, 8),
        support::config_with_credit(5, 1 << 20, 8, 8),
    );
    let stream = server.streams().open_bidi().unwrap();
    server.streams().send(stream, b"abcdefghij").unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut server, &mut client, now);

    assert_eq!(
        client.streams().recv_owned(stream).as_deref(),
        Some(&b"abcde"[..])
    );
    assert!(client.streams().recv_owned(stream).is_none());

    support::transfer(&mut workspace, &mut client, &mut server, now);
    support::transfer(&mut workspace, &mut server, &mut client, now);
    assert_eq!(
        client.streams().recv_owned(stream).as_deref(),
        Some(&b"fghij"[..])
    );
}

#[test]
fn inline_and_retained_segments_cross_as_one_stream() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let stream = server.streams().open_bidi().unwrap();
    server
        .streams()
        .send_buffer(stream, SendBuffer::inline(b"frame-").unwrap())
        .unwrap();
    server
        .streams()
        .send_buffer(
            stream,
            SendBuffer::Retained(Bytes::<Retained>::from(Shared::from_static(b"body"))),
        )
        .unwrap();
    server.streams().finish(stream).unwrap();

    support::transfer(&mut workspace, &mut server, &mut client, Instant::now());

    assert_eq!(
        client.streams().recv_owned(stream).as_deref(),
        Some(&b"frame-body"[..])
    );
    assert!(client.stream_state().recv_eof(stream));
}

#[test]
fn retired_receive_half_keeps_bidirectional_send_half_open() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, b"request").unwrap();
    client.streams().finish(stream).unwrap();

    let now = Instant::now();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    assert_eq!(
        server.streams().recv_owned(stream).as_deref(),
        Some(&b"request"[..])
    );
    assert!(server.stream_state().recv_eof(stream));

    server.streams().send(stream, b"response").unwrap();
    server.streams().finish(stream).unwrap();
    support::transfer(&mut workspace, &mut server, &mut client, now);
    assert_eq!(
        client.streams().recv_owned(stream).as_deref(),
        Some(&b"response"[..])
    );
    assert!(client.stream_state().recv_eof(stream));
}

#[test]
fn stop_sending_returns_a_reset_with_the_same_error() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let stream = server.streams().open_bidi().unwrap();
    server.streams().send(stream, b"unwanted").unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut server, &mut client, now);
    assert_eq!(
        client.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );
    client.streams().stop(stream, 0x99).unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    assert_eq!(server.stream_state().stopped(stream), Some(0x99));
    support::transfer(&mut workspace, &mut server, &mut client, now);
    assert_eq!(
        client.stream_events().poll_event(),
        Some(Event::Reset {
            stream_id: stream,
            error_code: 0x99,
        })
    );
    assert!(client.stream_state().recv_eof(stream));
}

#[test]
fn reset_supersedes_an_unpolled_readable_notice() {
    let (mut server, mut client, mut workspace) = support::connected_pair();
    let stream = client.streams().open_bidi().unwrap();
    let now = Instant::now();

    client.streams().send(stream, b"partial").unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    assert!(server.stream_state().has_events());

    client.streams().reset(stream, 0x51).unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Reset {
            stream_id: stream,
            error_code: 0x51,
        })
    );
    assert_eq!(server.stream_events().poll_event(), None);
}

#[test]
fn peer_stream_limits_are_enforced_by_the_allocator() {
    let (_, mut client, _workspace) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
        support::config_with_credit(1 << 20, 1 << 20, 1, 0),
    );
    assert_eq!(client.streams().open_bidi(), Ok(0));
    assert_eq!(client.streams().open_bidi(), Err(Error::PeerLimit));
    assert_eq!(client.streams().open_uni(), Err(Error::PeerLimit));
}

#[test]
fn local_capacity_is_distinct_from_peer_credit() {
    let server = support::config_with_credit(1 << 20, 1 << 20, 2, 0);
    let mut client = support::config_with_credit(1 << 20, 1 << 20, 2, 0);
    client.local_bidi_stream_capacity = 1;
    let (_, mut client, _workspace) = support::connected_pair_with(server, client);

    assert_eq!(client.streams().open_bidi(), Ok(0));
    assert_eq!(client.streams().open_bidi(), Err(Error::Capacity));
}

#[test]
fn local_bidi_capacity_returns_after_both_halves_retire() {
    let server_config = support::config_with_credit(1 << 20, 1 << 20, 2, 0);
    let mut client_config = support::config_with_credit(1 << 20, 1 << 20, 2, 0);
    client_config.local_bidi_stream_capacity = 1;
    let (mut server, mut client, mut workspace) =
        support::connected_pair_with(server_config, client_config);
    let stream = client.streams().open_bidi().unwrap();
    assert_eq!(client.streams().open_bidi(), Err(Error::Capacity));

    client.streams().send(stream, b"request").unwrap();
    client.streams().finish(stream).unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    assert_eq!(
        server.streams().recv_owned(stream).as_deref(),
        Some(&b"request"[..])
    );
    server.streams().send(stream, b"response").unwrap();
    server.streams().finish(stream).unwrap();
    support::transfer(&mut workspace, &mut server, &mut client, now);
    assert_eq!(client.streams().open_bidi(), Err(Error::Capacity));
    assert_eq!(
        client.streams().recv_owned(stream).as_deref(),
        Some(&b"response"[..])
    );

    for round in 1..=4 {
        let at = now + Duration::from_millis(round * 20);
        support::transfer(&mut workspace, &mut client, &mut server, at);
        support::transfer(&mut workspace, &mut server, &mut client, at);
    }
    assert_eq!(client.streams().open_bidi(), Ok(4));
}

#[test]
fn closed_bidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 2, 0),
        support::config_with_credit(1 << 20, 1 << 20, 2, 0),
    );
    let streams = [
        client.streams().open_bidi().unwrap(),
        client.streams().open_bidi().unwrap(),
    ];
    assert_eq!(client.streams().open_bidi(), Err(Error::PeerLimit));

    let now = Instant::now();
    for stream in streams {
        client.streams().send(stream, b"request").unwrap();
        client.streams().finish(stream).unwrap();
    }
    support::transfer(&mut workspace, &mut client, &mut server, now);
    for stream in streams {
        assert_eq!(
            server.streams().recv_owned(stream).as_deref(),
            Some(&b"request"[..]),
        );
        server.streams().send(stream, b"response").unwrap();
        server.streams().finish(stream).unwrap();
    }
    support::transfer(&mut workspace, &mut server, &mut client, now);
    for round in 1..=4 {
        let at = now + Duration::from_millis(round * 20);
        support::transfer(&mut workspace, &mut client, &mut server, at);
        support::transfer(&mut workspace, &mut server, &mut client, at);
    }

    assert_eq!(client.streams().open_bidi(), Ok(8));
}

#[test]
fn consumed_unidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 0, 2),
        support::config_with_credit(1 << 20, 1 << 20, 0, 2),
    );
    let streams = [
        client.streams().open_uni().unwrap(),
        client.streams().open_uni().unwrap(),
    ];
    assert_eq!(client.streams().open_uni(), Err(Error::PeerLimit));

    let now = Instant::now();
    for stream in streams {
        client.streams().send(stream, b"one-way").unwrap();
        client.streams().finish(stream).unwrap();
    }
    support::transfer(&mut workspace, &mut client, &mut server, now);
    for stream in streams {
        assert_eq!(
            server.streams().recv_owned(stream).as_deref(),
            Some(&b"one-way"[..]),
        );
    }
    support::transfer(&mut workspace, &mut server, &mut client, now);

    assert_eq!(client.streams().open_uni(), Ok(10));
}

#[test]
fn reset_unidirectional_streams_replenish_peer_credit() {
    let (mut server, mut client, mut workspace) = support::connected_pair_with(
        support::config_with_credit(1 << 20, 1 << 20, 0, 1),
        support::config_with_credit(1 << 20, 1 << 20, 0, 1),
    );
    let stream = client.streams().open_uni().unwrap();
    assert_eq!(client.streams().open_uni(), Err(Error::PeerLimit));

    client.streams().reset(stream, 0x42).unwrap();
    let now = Instant::now();
    support::transfer(&mut workspace, &mut client, &mut server, now);
    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Reset {
            stream_id: stream,
            error_code: 0x42,
        })
    );
    support::transfer(&mut workspace, &mut server, &mut client, now);

    assert!(client.streams().open_uni().is_ok());
}
