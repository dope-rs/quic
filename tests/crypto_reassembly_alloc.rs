pub mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use dope_quic::frame::Frame;
use dope_quic::varint::VarInt;

const INITIAL_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
const CLIENT_SCID: [u8; 4] = [1, 2, 3, 4];
const SERVER_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.get() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.get() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn sparse_packet(packet_number: u64, offset: u64) -> Vec<u8> {
    let mut frames = Vec::new();
    Frame::Crypto {
        offset: VarInt::new(offset).expect("small test offset"),
        data: vec![0],
    }
    .encode(&mut frames)
    .expect("valid CRYPTO frame");
    support::client_initial(&INITIAL_DCID, &CLIENT_SCID, packet_number, &frames)
}

#[test]
fn fragmented_crypto_acquires_one_workspace_then_never_allocates_per_range() {
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        INITIAL_DCID.to_vec(),
        SERVER_CID.to_vec(),
        CLIENT_SCID.to_vec(),
        support::signing_key(0x61),
        dope_quic::conn::config::Options::default(),
    )
    .unwrap();
    let mut workspace = dope_quic::conn::ReceiveWorkspace::new();
    let now = Instant::now();

    let mut first = sparse_packet(0, 1);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    let result = server.recv_packet(&mut workspace, &mut first, now);
    COUNTING.set(false);
    assert_eq!(result, Ok(()));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 1);

    for packet_number in 1..32 {
        let mut packet = sparse_packet(packet_number, packet_number * 2 + 1);
        ALLOCATIONS.store(0, Ordering::Relaxed);
        COUNTING.set(true);
        let result = server.recv_packet(&mut workspace, &mut packet, now);
        COUNTING.set(false);
        assert_eq!(result, Ok(()));
        assert_eq!(
            ALLOCATIONS.load(Ordering::Relaxed),
            0,
            "range {packet_number} allocated"
        );
    }
}
