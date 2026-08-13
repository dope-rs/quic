pub mod support;

use std::cell::Cell;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dope_quic::{Handler, conn};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn record_allocation(_size: usize) {
    if COUNTING.get() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: support::Allocator = support::Allocator::new(record_allocation);

struct Noop;

impl Handler<0> for Noop {
    type Connection = ();

    fn create_connection(
        &mut self,
        _conn: &mut dope_quic::conn::session::Connection,
        _handle: dope_quic::conn::Handle,
    ) {
    }
}

#[test]
fn deadline_and_close_bookkeeping_do_not_allocate() {
    let now = Instant::now();
    let mut config = conn::config::Options::default();
    config.transport_params.max_idle_timeout_ms = 1;
    let mut mux = dope_quic::mux::setup::Client::new(Noop)
        .limits(1, 8, 16 << 10)
        .build()
        .unwrap();
    mux.protocol()
        .connect(
            "10.0.0.2:443".parse().unwrap(),
            [7; 32],
            config,
            vec![0x42; 8],
            now,
        )
        .unwrap();
    mux.output().drain().for_each(drop);
    let deadline = mux.next_deadline(now).unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    for _ in 0..4096 {
        black_box(mux.next_deadline(now));
        mux.output().drive_bounded(now);
    }
    // RFC 9000 requires the effective idle timeout to be at least 3×PTO, so the
    // first deadline can be a loss timer rather than the configured 1ms idle timer.
    mux.output()
        .drive_bounded(deadline + Duration::from_secs(5));
    COUNTING.set(false);

    assert_eq!(mux.active_conns(), 0);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    deadline_heap_advances_only_due_connection();
}

fn deadline_heap_advances_only_due_connection() {
    let first_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let second_addr: SocketAddr = "10.0.0.3:443".parse().unwrap();
    let now = Instant::now();
    let mut mux = dope_quic::mux::setup::Client::new(Noop)
        .limits(2, 8, 16 << 10)
        .build()
        .unwrap();
    mux.protocol()
        .connect(
            first_addr,
            [1; 32],
            conn::config::Options::default(),
            vec![1; 8],
            now,
        )
        .unwrap();
    mux.output().drive_bounded(now);
    mux.output().drain().for_each(drop);
    mux.protocol()
        .connect(
            second_addr,
            [2; 32],
            conn::config::Options::default(),
            vec![2; 8],
            now + Duration::from_millis(100),
        )
        .unwrap();
    mux.output().drive_bounded(now + Duration::from_millis(100));
    mux.output().drain().for_each(drop);

    let deadline = mux.next_deadline(now).unwrap();
    mux.output()
        .drive_bounded(deadline + Duration::from_micros(1));
    let destinations = mux
        .output()
        .drain()
        .map(|outgoing| outgoing.addr())
        .collect::<Vec<_>>();

    assert!(!destinations.is_empty());
    assert!(destinations.iter().all(|addr| *addr == first_addr));
}
