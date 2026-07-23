use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dope_quic::conn::PacketBatch;
use dope_quic::{Conn, ServerConn, conn, transport_params};
use shin::sig::SigningKey;

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

fn config() -> conn::Config {
    conn::Config {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_streams_bidi: 8,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn established() -> (Conn, ServerConn) {
    let cid = vec![0x71; 8];
    let signing = SigningKey::from_seed(&[0x39; 32]).unwrap();
    let public_key = *signing.pubkey().unwrap();
    let mut server =
        Conn::new_server(cid.clone(), cid.clone(), cid.clone(), signing, config()).unwrap();
    let mut client = Conn::new_client(cid.clone(), cid, public_key, config()).unwrap();
    let now = Instant::now();
    for _ in 0..6 {
        for packet in client.send_packets(now) {
            server.recv_packet(&packet, now).unwrap();
        }
        for packet in server.send_packets(now) {
            client.recv_packet(&packet, now).unwrap();
        }
    }
    assert!(client.is_established() && server.is_established());
    (client, server)
}

#[test]
fn warmed_one_rtt_send_and_decrypt_do_not_allocate() {
    let (mut client, mut server) = established();
    let payload = vec![0x5a; 4096];
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, &payload).unwrap();
    let mut batch = PacketBatch::default();
    let now = Instant::now() + Duration::from_secs(1);
    client.send_batch(&mut batch, now, 1, 1200);
    assert_eq!(batch.packets(), 1);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    client.send_batch(&mut batch, now + Duration::from_secs(1), 1, 1200);
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "last allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );

    let packet_now = now + Duration::from_secs(2);
    let packet = client.send_packets(packet_now).into_iter().next().unwrap();
    server.recv_packet(&packet, packet_now).unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    server.recv_packet(&packet, packet_now).unwrap();
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "last allocation size {}",
        LAST_SIZE.load(Ordering::Relaxed)
    );
}
