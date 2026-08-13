#[allow(dead_code)]
mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dope_quic::conn::packet::Batch;
use dope_quic::conn::server;
use dope_quic::{conn, conn::session::Connection, transport_params};
use shin::crypto::sig::SigningKey;

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static LAST_SIZE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            LAST_SIZE.store(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            LAST_SIZE.store(size, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn config() -> conn::config::Options {
    conn::config::Options {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            initial_max_streams_bidi: 8,
            initial_max_streams_uni: 8,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn established() -> (Connection, server::Connection, conn::ReceiveWorkspace) {
    let cid = vec![0x71; 8];
    let signing = SigningKey::from_seed(&[0x39; 32]).unwrap();
    let public_key = *signing.pubkey().unwrap();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        cid.clone(),
        cid.clone(),
        cid.clone(),
        signing,
        config(),
    )
    .unwrap();
    let mut client =
        dope_quic::conn::setup::Client::<0>::connect(cid.clone(), cid, public_key, config())
            .unwrap();
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    for _ in 0..6 {
        for mut packet in client.transmit().send(now) {
            server
                .recv_packet(&mut workspace, &mut packet, now)
                .unwrap();
        }
        for mut packet in server.transmit().send(now) {
            client
                .recv_packet(&mut workspace, &mut packet, now)
                .unwrap();
        }
    }
    assert!(client.status().is_established() && server.status().is_established());
    (client, server, workspace)
}

#[test]
fn warmed_one_rtt_send_and_decrypt_do_not_allocate() {
    initial_crypto_pto_does_not_allocate();
    maximal_receive_plan_does_not_allocate();
    let (mut client, mut server, mut workspace) = established();
    let payload = vec![0x5a; 4096];
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, &payload).unwrap();
    let mut batch = Batch::default();
    let now = Instant::now() + Duration::from_secs(1);
    client.transmit().send_batch(&mut batch, now, 1, 1200);
    assert_eq!(batch.packets(), 1);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    client
        .transmit()
        .send_batch(&mut batch, now + Duration::from_secs(1), 1, 1200);
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "last allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );

    let packet_now = now + Duration::from_secs(2);
    let mut packet = client
        .transmit()
        .send(packet_now)
        .into_iter()
        .next()
        .unwrap();
    let mut duplicate = packet.clone();
    server
        .recv_packet(&mut workspace, &mut packet, packet_now)
        .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    server
        .recv_packet(&mut workspace, &mut duplicate, packet_now)
        .unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "last allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );

    out_of_order_stream_ack_bookkeeping_does_not_allocate();
    ack_generation_does_not_allocate();
    recurring_stream_event_does_not_allocate();
    first_receive_stream_state_does_not_allocate();
    recycled_receive_stream_state_does_not_allocate();
    first_send_stream_state_does_not_allocate();
    recycled_send_stream_state_does_not_allocate();
    recurring_control_delivery_does_not_allocate();
}

fn maximal_receive_plan_does_not_allocate() {
    const INITIAL_DCID: [u8; 8] = [0x81; 8];
    const CLIENT_SCID: [u8; 8] = [0x82; 8];
    const SERVER_CID: [u8; 8] = [0x83; 8];

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        INITIAL_DCID.to_vec(),
        SERVER_CID.to_vec(),
        CLIENT_SCID.to_vec(),
        support::signing_key(0x84),
        config(),
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();
    let now = Instant::now();
    let mut warm = support::client_initial(
        &INITIAL_DCID,
        &CLIENT_SCID,
        0,
        &[dope_quic::frame::TYPE_PING],
    );
    server.recv_packet(&mut workspace, &mut warm, now).unwrap();

    let frames = [dope_quic::frame::TYPE_PING; 256];
    let mut packet = support::client_initial(&INITIAL_DCID, &CLIENT_SCID, 1, &frames);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    server
        .recv_packet(&mut workspace, &mut packet, now)
        .unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "maximal receive plan allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn initial_crypto_pto_does_not_allocate() {
    let cid = vec![0x72; 8];
    let signing = SigningKey::from_seed(&[0x38; 32]).unwrap();
    let public_key = *signing.pubkey().unwrap();
    let mut client =
        dope_quic::conn::setup::Client::<0>::connect(cid.clone(), cid, public_key, config())
            .unwrap();
    let mut batch = Batch::default();
    let sent_at = Instant::now();
    client.transmit().send_batch(&mut batch, sent_at, 1, 1_200);
    assert_eq!(batch.packets(), 1);
    let deadline = client.status().next_timer().expect("Initial PTO");

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    conn::recovery::Loss::new(&mut client).check_loss(deadline);
    client.transmit().send_batch(&mut batch, deadline, 1, 1_200);
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "Initial CRYPTO PTO allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn recurring_control_delivery_does_not_allocate() {
    let (mut client, _, _workspace) = established();
    let mut batch = Batch::default();
    let now = Instant::now() + Duration::from_secs(20);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    client.send_path_challenge(1u64.to_ne_bytes());
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "first control owner allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );

    client.transmit().send_batch(&mut batch, now, 1, 1200);
    assert_eq!(batch.packets(), 1);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    client.send_path_challenge(2u64.to_ne_bytes());
    client
        .transmit()
        .send_batch(&mut batch, now + Duration::from_millis(1), 1, 1200);
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "recurring control allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn first_send_stream_state_does_not_allocate() {
    let (mut client, _, _workspace) = established();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let stream = client.streams().open_uni().unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "first send-stream state allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
    client.streams().finish(stream).unwrap();
}

fn recycled_send_stream_state_does_not_allocate() {
    let (mut client, mut server, mut workspace) = established();
    let first_stream = client.streams().open_uni().unwrap();
    client.streams().send(first_stream, &[0x61; 512]).unwrap();
    client.streams().finish(first_stream).unwrap();
    let now = Instant::now() + Duration::from_secs(6);

    // Deliver and acknowledge the FIN so the sender retires the state and
    // returns both its indexed slot and warmed payload storage to the map.
    for turn in 0..6 {
        let packet_now = now + Duration::from_millis(turn);
        for mut packet in client.transmit().send(packet_now) {
            server
                .recv_packet(&mut workspace, &mut packet, packet_now)
                .unwrap();
        }
        for mut packet in server.transmit().send(packet_now) {
            client
                .recv_packet(&mut workspace, &mut packet, packet_now)
                .unwrap();
        }
    }

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let second_stream = client.streams().open_uni().unwrap();
    client.streams().send(second_stream, &[0x62; 128]).unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "recycled send-stream allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn first_receive_stream_state_does_not_allocate() {
    use dope_quic::conn::stream::Event;

    let (mut client, mut server, mut workspace) = established();
    let stream = client.streams().open_uni().unwrap();
    client.streams().finish(stream).unwrap();
    let now = Instant::now() + Duration::from_secs(4);
    let mut packets = client.transmit().send(now);
    assert!(!packets.is_empty());

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for packet in &mut packets {
        server.recv_packet(&mut workspace, packet, now).unwrap();
    }
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "first receive-stream state allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn recycled_receive_stream_state_does_not_allocate() {
    use dope_quic::conn::stream::Event;

    let (mut client, mut server, mut workspace) = established();
    let now = Instant::now() + Duration::from_secs(4);
    let first_stream = client.streams().open_uni().unwrap();
    client.streams().send(first_stream, &[0x51; 512]).unwrap();
    client.streams().finish(first_stream).unwrap();
    let mut first_packets = client.transmit().send(now);
    assert!(!first_packets.is_empty());
    for packet in &mut first_packets {
        server.recv_packet(&mut workspace, packet, now).unwrap();
    }
    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable {
            stream_id: first_stream
        })
    );

    // Retiring the stream returns its indexed state while retaining the
    // contiguous receive allocation for the next stream on this connection.
    let mut received = vec![0];
    assert_eq!(server.streams().recv(first_stream, &mut received), 512);
    assert!(server.stream_state().recv_eof(first_stream));

    let second_stream = client.streams().open_uni().unwrap();
    client.streams().send(second_stream, &[0x52; 128]).unwrap();
    client.streams().finish(second_stream).unwrap();
    let packet_now = now + Duration::from_millis(1);
    let mut second_packets = client.transmit().send(packet_now);
    assert!(!second_packets.is_empty());

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for packet in &mut second_packets {
        server
            .recv_packet(&mut workspace, packet, packet_now)
            .unwrap();
    }
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable {
            stream_id: second_stream
        })
    );
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "recycled receive-stream allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn recurring_stream_event_does_not_allocate() {
    use dope_quic::conn::stream::Event;

    let (mut client, mut server, mut workspace) = established();
    let stream = client.streams().open_bidi().unwrap();
    let now = Instant::now() + Duration::from_secs(3);

    client.streams().send(stream, &[0x41; 512]).unwrap();
    let mut first = client.transmit().send(now).into_iter().next().unwrap();
    server.recv_packet(&mut workspace, &mut first, now).unwrap();
    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );

    // A non-empty destination makes RecvStream retain its warmed allocation.
    let mut received = vec![0];
    assert_eq!(server.streams().recv(stream, &mut received), 512);
    received.clear();

    client.streams().send(stream, &[0x42; 128]).unwrap();
    let packet_now = now + Duration::from_millis(1);
    let mut second = client
        .transmit()
        .send(packet_now)
        .into_iter()
        .next()
        .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    server
        .recv_packet(&mut workspace, &mut second, packet_now)
        .unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        server.stream_events().poll_event(),
        Some(Event::Readable { stream_id: stream })
    );
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "recurring stream event allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn ack_generation_does_not_allocate() {
    let (mut client, mut server, mut workspace) = established();
    let stream = client.streams().open_bidi().unwrap();
    let now = Instant::now() + Duration::from_secs(5);

    client.streams().send(stream, &[0x31; 2_048]).unwrap();
    let mut packets = client.transmit().send(now);
    assert!(packets.len() >= 2);
    server
        .recv_packet(&mut workspace, &mut packets[0], now)
        .unwrap();

    let mut batch = Batch::default();
    server
        .transmit()
        .send_batch(&mut batch, now + Duration::from_millis(1), 1, 1_200);
    assert_eq!(batch.packets(), 1);

    client.streams().send(stream, &[0x32; 128]).unwrap();
    let mut packet = client
        .transmit()
        .send(now + Duration::from_millis(2))
        .into_iter()
        .next()
        .unwrap();
    server
        .recv_packet(&mut workspace, &mut packet, now + Duration::from_millis(2))
        .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    server
        .transmit()
        .send_batch(&mut batch, now + Duration::from_millis(3), 1, 1_200);
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "ACK generation allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}

fn out_of_order_stream_ack_bookkeeping_does_not_allocate() {
    let (mut client, mut server, mut workspace) = established();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, &[0x6b; 8192]).unwrap();
    client.streams().finish(stream).unwrap();
    let now = Instant::now() + Duration::from_secs(10);
    let mut packets = client.transmit().send(now);
    assert!(packets.len() >= 3);
    let mut first = packets.remove(0);

    let mut fragmented = false;
    for packet in packets.iter_mut() {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
        server.recv_packet(&mut workspace, packet, now).unwrap();
        COUNTING.store(false, Ordering::Relaxed);
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        assert!(
            allocations <= 1,
            "out-of-order DATA allocated metadata in addition to its payload, last size {}",
            LAST_SIZE.load(Ordering::Relaxed)
        );
        fragmented |= allocations == 1;
    }
    assert!(fragmented, "the allocation proof must exercise a DATA gap");
    let suffix_ack = server.transmit().send(now + Duration::from_millis(1));
    assert!(!suffix_ack.is_empty());
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for mut packet in suffix_ack {
        client
            .recv_packet(&mut workspace, &mut packet, now + Duration::from_millis(1))
            .unwrap();
    }
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "suffix ACK allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );

    server.recv_packet(&mut workspace, &mut first, now).unwrap();
    let prefix_ack = server.transmit().send(now + Duration::from_millis(2));
    assert!(!prefix_ack.is_empty());
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for mut packet in prefix_ack {
        client
            .recv_packet(&mut workspace, &mut packet, now + Duration::from_millis(2))
            .unwrap();
    }
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "prefix collapse allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
    assert_eq!(
        server.streams().recv_owned(stream).as_deref(),
        Some(&[0x6b; 8192][..])
    );
}
