use std::time::Instant;

use dope_quic::frame::Frame;
use dope_quic::stream::{RecvStream, SendStream};
use dope_quic::{Conn, ConnConfig, StreamError, StreamEvent, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const HS_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

fn handshake_pair() -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let cfg = || ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
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

fn drain(from: &mut Conn, into: &mut Conn) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

#[test]
fn stream_minimal_form_round_trip() {
    let f = Frame::Stream {
        stream_id: 4,
        offset: 0,
        fin: false,
        length_prefixed: false,
        data: b"hello".to_vec(),
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf[0], 0x08);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn stream_with_offset_and_length_round_trip() {
    let f = Frame::Stream {
        stream_id: 1,
        offset: 16384,
        fin: false,
        length_prefixed: true,
        data: b"chunk".to_vec(),
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf[0], 0x0e, "OFF (0x04) | LEN (0x02) but not FIN ⇒ 0x0e",);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn stream_fin_flag_round_trip() {
    let f = Frame::Stream {
        stream_id: 12,
        offset: 0,
        fin: true,
        length_prefixed: true,
        data: vec![],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf[0], 0x0b, "LEN (0x02) | FIN (0x01) ⇒ 0x0b");
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn stream_all_eight_type_variants_round_trip() {
    for ty in 0x08u8..=0x0f {
        let has_off = ty & 0x04 != 0;
        let has_len = ty & 0x02 != 0;
        let fin = ty & 0x01 != 0;
        let f = Frame::Stream {
            stream_id: 8,
            offset: if has_off { 100 } else { 0 },
            fin,
            length_prefixed: has_len,
            data: b"abc".to_vec(),
        };
        let mut buf = Vec::new();
        f.encode(&mut buf);
        assert_eq!(buf[0], ty, "encoded type byte for variant 0x{:02x}", ty);
        let (decoded, _) = Frame::decode(&buf).unwrap();
        assert_eq!(decoded, f, "decode mismatch for variant 0x{:02x}", ty);
    }
}

#[test]
fn stream_bare_form_consumes_rest_of_buffer() {
    let f = Frame::Stream {
        stream_id: 0,
        offset: 0,
        fin: false,
        length_prefixed: false,
        data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    let frames = Frame::decode_all(&buf).unwrap();
    assert_eq!(frames, vec![f]);
}

#[test]
fn reset_stream_round_trip() {
    let f = Frame::ResetStream {
        stream_id: 4,
        error_code: 0x42,
        final_size: 12345,
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf[0], 0x04);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn stop_sending_round_trip() {
    let f = Frame::StopSending {
        stream_id: 8,
        error_code: 0x7,
    };
    let mut buf = Vec::new();
    f.encode(&mut buf);
    assert_eq!(buf[0], 0x05);
    let (decoded, n) = Frame::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!(decoded, f);
}

#[test]
fn recv_in_order_chunks_deliver_immediately() {
    let mut rs = RecvStream::default();
    rs.on_chunk(0, b"hello ", false);
    let mut out = Vec::new();
    assert_eq!(rs.read(&mut out), 6);
    assert_eq!(&out, b"hello ");

    rs.on_chunk(6, b"world", false);
    out.clear();
    assert_eq!(rs.read(&mut out), 5);
    assert_eq!(&out, b"world");
}

#[test]
fn recv_out_of_order_buffers_until_gap_closes() {
    let mut rs = RecvStream::default();
    rs.on_chunk(5, b"world", false);
    let mut out = Vec::new();
    assert_eq!(rs.read(&mut out), 0, "no contiguous bytes available yet");

    rs.on_chunk(0, b"hello", false);
    out.clear();
    assert_eq!(rs.read(&mut out), 10, "both chunks delivered as one run");
    assert_eq!(&out, b"helloworld");
}

#[test]
fn recv_three_chunks_arbitrary_order() {
    let mut rs = RecvStream::default();
    rs.on_chunk(8, b"CCCC", false);
    rs.on_chunk(0, b"AAAA", false);
    let mut out = Vec::new();
    assert_eq!(rs.read(&mut out), 4);
    assert_eq!(&out, b"AAAA");

    rs.on_chunk(4, b"BBBB", false);
    out.clear();
    assert_eq!(rs.read(&mut out), 8);
    assert_eq!(&out, b"BBBBCCCC");
}

#[test]
fn recv_overlap_with_already_delivered_is_dropped() {
    let mut rs = RecvStream::default();
    rs.on_chunk(0, b"abcdef", false);
    let mut out = Vec::new();
    rs.read(&mut out);
    rs.on_chunk(2, b"cdefgh", false);
    out.clear();
    assert_eq!(rs.read(&mut out), 2, "only the new tail (gh) is delivered");
    assert_eq!(&out, b"gh");
}

#[test]
fn recv_fin_marks_size_and_is_eof_only_after_drain() {
    let mut rs = RecvStream::default();
    rs.on_chunk(0, b"final", true);
    assert_eq!(rs.final_size(), Some(5));
    assert!(!rs.is_eof(), "FIN observed but not yet drained");
    let mut out = Vec::new();
    rs.read(&mut out);
    assert_eq!(&out, b"final");
    assert!(rs.is_eof(), "all bytes drained past final_size");
}

#[test]
fn recv_fin_on_empty_chunk_after_data() {
    let mut rs = RecvStream::default();
    rs.on_chunk(0, b"data", false);
    rs.on_chunk(4, b"", true);
    assert_eq!(rs.final_size(), Some(4));
    let mut out = Vec::new();
    rs.read(&mut out);
    assert_eq!(&out, b"data");
    assert!(rs.is_eof());
}

#[test]
fn recv_fin_with_pending_gap_not_eof_until_filled() {
    let mut rs = RecvStream::default();
    rs.on_chunk(0, b"AB", false);
    rs.on_chunk(4, b"EF", true);
    assert_eq!(rs.final_size(), Some(6));
    let mut out = Vec::new();
    assert_eq!(rs.read(&mut out), 2, "only the contiguous prefix");
    assert_eq!(&out, b"AB");
    assert!(!rs.is_eof(), "gap [2,4) still missing");

    rs.on_chunk(2, b"CD", false);
    out.clear();
    rs.read(&mut out);
    assert_eq!(&out, b"CDEF");
    assert!(rs.is_eof());
}

#[test]
fn send_stream_buffers_and_pops_with_offset() {
    let mut s = SendStream::default();
    s.write(b"hello ");
    s.write(b"world");
    let (off, slice) = s.unsent();
    assert_eq!(off, 0);
    assert_eq!(slice, b"hello world");
    let n = slice.len();
    let fin = s.would_fin(n);
    assert!(!fin, "fin not marked yet");
    s.advance_sent(n, fin);
    assert!(!s.has_pending(), "buffer drained");

    s.write(b"!");
    s.mark_fin();
    let (off, slice) = s.unsent();
    assert_eq!(off, 11, "next offset advances past prior pop");
    assert_eq!(slice, b"!");
    let n = slice.len();
    let fin = s.would_fin(n);
    assert!(fin, "fin emitted as buffer drained to empty");
    s.advance_sent(n, fin);
    assert!(s.fin_sent());
    assert!(!s.has_pending());
    assert!(s.blocked(), "no more frames after fin_sent");
}

#[test]
fn send_stream_fin_only_pops_empty_chunk_with_fin() {
    let mut s = SendStream::default();
    s.mark_fin();
    let (off, slice) = s.unsent();
    assert_eq!(off, 0);
    assert!(slice.is_empty());
    assert!(s.would_fin(0));
    s.advance_sent(0, true);
    assert!(s.fin_sent());
}

#[test]
fn send_stream_pop_respects_max_bytes() {
    let mut s = SendStream::default();
    s.write(b"abcdefghij");
    let (_, slice) = s.unsent();
    let n = 4.min(slice.len());
    assert_eq!(&slice[..n], b"abcd");
    let fin1 = s.would_fin(n);
    assert!(!fin1);
    s.advance_sent(n, fin1);
    let (off2, slice2) = s.unsent();
    assert_eq!(off2, 4);
    assert_eq!(slice2, b"efghij");
}

#[test]
fn send_stream_ack_drains_acked_prefix() {
    let mut s = SendStream::default();
    s.write(b"abcdefghij");
    let (_, slice) = s.unsent();
    let n = slice.len();
    s.advance_sent(n, false);
    s.ack(0, 4);
    assert_eq!(
        s.chunk_at(0, 4),
        None,
        "acked prefix drained, no longer addressable"
    );
    assert_eq!(
        s.chunk_at(4, 6),
        Some(&b"efghij"[..]),
        "unacked tail retained for retransmit"
    );
    s.ack(7, 3);
    assert_eq!(
        s.chunk_at(4, 3),
        Some(&b"efg"[..]),
        "non-contiguous ack does not drain the hole at offset 4"
    );
    s.ack(4, 3);
    assert_eq!(s.chunk_at(4, 6), None, "contiguous fill drains the rest");
}

#[test]
fn end_to_end_server_writes_client_reads_in_order() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(4, b"hello over quic streams");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    let n = client.stream_recv(4, &mut got);
    assert_eq!(n, 23);
    assert_eq!(&got, b"hello over quic streams");
    assert!(!client.stream_recv_eof(4), "no FIN sent yet");
}

#[test]
fn end_to_end_fin_propagates_eof_to_recv_side() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(8, b"final-payload");
    server.stream_send_fin(8);
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(8, &mut got);
    assert_eq!(&got, b"final-payload");
    assert!(client.stream_recv_eof(8), "FIN drained ⇒ stream is EOF");
}

#[test]
fn end_to_end_two_writes_one_packet_arrives_concatenated() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(0, b"part-A:");
    server.stream_send(0, b"part-B");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(0, &mut got);
    assert_eq!(&got, b"part-A:part-B");
}

#[test]
fn end_to_end_bidirectional_streams_independent_buffers() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(4, b"s2c");
    client.stream_send(0, b"c2s");
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);

    let mut s = Vec::new();
    client.stream_recv(4, &mut s);
    assert_eq!(&s, b"s2c");

    let mut c = Vec::new();
    server.stream_recv(0, &mut c);
    assert_eq!(&c, b"c2s");
}

#[test]
fn flow_control_frames_round_trip() {
    let cases = [
        Frame::MaxData {
            maximum_data: 1_000_000,
        },
        Frame::MaxStreamData {
            stream_id: 4,
            maximum_stream_data: 65_536,
        },
        Frame::DataBlocked {
            maximum_data: 12_345,
        },
        Frame::StreamDataBlocked {
            stream_id: 0,
            maximum_stream_data: 0,
        },
    ];
    for f in cases {
        let mut buf = Vec::new();
        f.encode(&mut buf);
        let (decoded, n) = Frame::decode(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(decoded, f);
    }
}

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
fn send_blocked_by_per_stream_credit() {
    let (mut server, mut client) = handshake_pair_with_credit(5, 1 << 20);
    server.stream_send(4, b"abcdefghij");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(4, &mut got);
    assert_eq!(
        &got, b"abcde",
        "only the first 5 bytes pass per-stream credit"
    );
}

#[test]
fn send_resumes_after_recv_side_max_stream_data_emit() {
    let (mut server, mut client) = handshake_pair_with_credit(5, 1 << 20);
    server.stream_send(4, b"abcdefghij");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(4, &mut got);
    assert_eq!(&got, b"abcde");

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    got.clear();
    client.stream_recv(4, &mut got);
    assert_eq!(
        &got, b"fghij",
        "remainder flows after MAX_STREAM_DATA round-trip"
    );
}

#[test]
fn send_blocked_by_connection_credit() {
    let (mut server, mut client) = handshake_pair_with_credit(1 << 20, 4);
    server.stream_send(0, b"AAAA");
    server.stream_send(4, b"BBBB");
    drain(&mut server, &mut client);
    let mut a = Vec::new();
    let mut b = Vec::new();
    client.stream_recv(0, &mut a);
    client.stream_recv(4, &mut b);
    assert_eq!(a.len() + b.len(), 4, "total emitted ≤ initial_max_data");
}

#[test]
fn streams_lifecycle_frames_round_trip() {
    let cases = [
        Frame::MaxStreams {
            is_uni: false,
            max_streams: 100,
        },
        Frame::MaxStreams {
            is_uni: true,
            max_streams: 50,
        },
        Frame::StreamsBlocked {
            is_uni: false,
            max_streams: 0,
        },
        Frame::StreamsBlocked {
            is_uni: true,
            max_streams: 7,
        },
    ];
    for f in cases {
        let mut buf = Vec::new();
        f.encode(&mut buf);
        let (decoded, n) = Frame::decode(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(decoded, f);
    }
}

#[test]
fn local_stream_allocator_uses_role_correct_ids() {
    let (mut server, mut client) = handshake_pair();

    assert_eq!(client.open_bidi_stream().unwrap(), 0);
    assert_eq!(client.open_bidi_stream().unwrap(), 4);
    assert_eq!(client.open_uni_stream().unwrap(), 2);
    assert_eq!(server.open_bidi_stream().unwrap(), 1);
    assert_eq!(server.open_uni_stream().unwrap(), 3);
}

#[test]
fn local_stream_allocator_respects_peer_limit() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let cfg = || ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            initial_max_streams_bidi: 1,
            initial_max_streams_uni: 0,
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

    assert_eq!(client.open_bidi_stream(), Ok(0));
    assert_eq!(client.open_bidi_stream(), Err(StreamError::PeerLimit));
    assert_eq!(client.open_uni_stream(), Err(StreamError::PeerLimit));
}

#[test]
fn stream_events_announce_readable_fin_reset_and_stop() {
    let (mut server, mut client) = handshake_pair();
    let stream_id = client.open_bidi_stream().unwrap();
    client.stream_send(stream_id, b"hello");
    client.stream_send_fin(stream_id);
    drain(&mut client, &mut server);

    assert_eq!(
        server.poll_stream_event(),
        Some(StreamEvent::Data { stream_id })
    );
    assert_eq!(
        server.poll_stream_event(),
        Some(StreamEvent::Finished { stream_id })
    );
    let mut got = Vec::new();
    server.stream_recv(stream_id, &mut got);
    assert_eq!(&got, b"hello");
    assert!(server.stream_recv_eof(stream_id));

    server.stream_stop_sending(stream_id, 0x55);
    drain(&mut server, &mut client);
    assert_eq!(
        client.poll_stream_event(),
        Some(StreamEvent::Stopped {
            stream_id,
            error_code: 0x55
        })
    );

    drain(&mut client, &mut server);
    assert_eq!(
        server.poll_stream_event(),
        Some(StreamEvent::Reset {
            stream_id,
            error_code: 0x55
        })
    );
}

#[test]
fn end_to_end_reset_stream_propagates_to_recv_side() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(4, b"partial");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(4, &mut got);
    assert_eq!(&got, b"partial");

    server.stream_reset(4, 0x42);
    drain(&mut server, &mut client);

    assert_eq!(client.stream_recv_reset(4), Some(0x42));
    assert!(
        client.stream_recv_fin_received(4),
        "RESET_STREAM nails the final size",
    );
}

#[test]
fn end_to_end_stop_sending_triggers_reset_response() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(4, b"unwanted");
    drain(&mut server, &mut client);

    client.stream_stop_sending(4, 0x99);
    drain(&mut client, &mut server);
    assert_eq!(server.stream_send_stopped(4), Some(0x99));

    drain(&mut server, &mut client);
    assert_eq!(
        client.stream_recv_reset(4),
        Some(0x99),
        "auto-RESET_STREAM uses the same error code",
    );
}

#[test]
fn stream_after_reset_drops_further_writes() {
    let (mut server, mut client) = handshake_pair();
    server.stream_send(4, b"hello");
    server.stream_reset(4, 1);
    server.stream_send(4, b"too late");
    drain(&mut server, &mut client);
    let mut got = Vec::new();
    client.stream_recv(4, &mut got);
    assert!(got.is_empty() || got == b"hello");
    assert_eq!(client.stream_recv_reset(4), Some(1));
}

#[test]
fn stream_in_a_run_with_other_frames_decodes_in_order() {
    let f1 = Frame::Ping;
    let f2 = Frame::Stream {
        stream_id: 4,
        offset: 0,
        fin: false,
        length_prefixed: true,
        data: b"abc".to_vec(),
    };
    let f3 = Frame::ResetStream {
        stream_id: 4,
        error_code: 1,
        final_size: 3,
    };
    let mut buf = Vec::new();
    f1.encode(&mut buf);
    f2.encode(&mut buf);
    f3.encode(&mut buf);
    let frames = Frame::decode_all(&buf).unwrap();
    assert_eq!(frames, vec![f1, f2, f3]);
}
