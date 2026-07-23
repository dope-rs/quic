use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dope_quic::{Handler, Mux, conn};

struct Allocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Noop;

impl Handler for Noop {}

#[test]
fn deadline_and_close_bookkeeping_do_not_allocate() {
    let now = Instant::now();
    let mut config = conn::Config::default();
    config.transport_params.max_idle_timeout_ms = 1;
    let mut mux = Mux::client_with_limits(Noop, 1, 8, 16 << 10).unwrap();
    mux.connect(
        "10.0.0.2:443".parse().unwrap(),
        [7; 32],
        config,
        vec![0x42; 8],
        now,
    )
    .unwrap();
    mux.drain_outgoing().for_each(drop);
    let deadline = mux.next_deadline(now).unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    for _ in 0..4096 {
        black_box(mux.next_deadline(now));
        mux.reap_closed(now);
    }
    // RFC 9000 requires the effective idle timeout to be at least 3×PTO, so the
    // first deadline can be a loss timer rather than the configured 1ms idle timer.
    mux.reap_closed(deadline + Duration::from_secs(5));
    COUNTING.store(false, Ordering::Relaxed);

    assert_eq!(mux.active_conns(), 0);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    deadline_heap_advances_only_due_connection();
}

fn deadline_heap_advances_only_due_connection() {
    let first_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let second_addr: SocketAddr = "10.0.0.3:443".parse().unwrap();
    let now = Instant::now();
    let mut mux = Mux::client_with_limits(Noop, 2, 8, 16 << 10).unwrap();
    mux.connect(
        first_addr,
        [1; 32],
        conn::Config::default(),
        vec![1; 8],
        now,
    )
    .unwrap();
    mux.connect(
        second_addr,
        [2; 32],
        conn::Config::default(),
        vec![2; 8],
        now + Duration::from_millis(100),
    )
    .unwrap();
    mux.drain_outgoing().for_each(drop);

    let deadline = mux.next_deadline(now).unwrap();
    mux.reap_closed(deadline + Duration::from_micros(1));
    let destinations = mux
        .drain_outgoing()
        .map(|outgoing| outgoing.addr())
        .collect::<Vec<_>>();

    assert!(!destinations.is_empty());
    assert!(destinations.iter().all(|addr| *addr == first_addr));
}
