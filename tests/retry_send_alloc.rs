use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use dope_quic::conn;
use dope_quic::conn::session::Connection;
use dope_quic::packet::{InitialHeader, QUIC_V1, RetryPacketRef};
use dope_quic::{Handler, mux::Outgoing};
use shin::crypto::sig::SigningKey;

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Noop;

impl Handler<0> for Noop {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: conn::Handle) {}
}

#[test]
fn control_transmit_allocates_once_cold_and_zero_times_after_recycling() {
    let options = conn::config::Options {
        require_address_validation: true,
        retry_token_secret: Some([0xa5; 32]),
        ..Default::default()
    };
    let signing = SigningKey::from_seed(&[0x39; 32]).expect("signing key");
    let mut mux =
        dope_quic::mux::setup::Server::accept(Noop, signing, options).expect("server setup");
    let original_dcid = [0x11; 8];
    let client_scid = [0x22; 8];
    let (mut initial, _) = InitialHeader {
        version: QUIC_V1,
        dcid: original_dcid.to_vec(),
        scid: client_scid.to_vec(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 1,
    }
    .encode_with_pn(100)
    .expect("encode Initial");
    initial.resize(initial.len() + 100, 0);
    let source: SocketAddr = "127.0.0.1:55001".parse().expect("source address");

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let received = mux.protocol().recv(source, &mut initial, Instant::now());
    COUNTING.store(false, Ordering::Relaxed);

    received.expect("receive Initial");
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 1, "cold Retry");
    let outgoing = mux.output().drain().next().expect("one Retry");
    assert!(matches!(&outgoing, Outgoing::Suffix(..)));
    let retry = RetryPacketRef::decode(outgoing.payload()).expect("decode Retry");
    assert_eq!(retry.destination_connection_id(), client_scid);
    let allocation = outgoing.payload().as_ptr();
    mux.output().recycle(outgoing);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let received = mux.protocol().recv(source, &mut initial, Instant::now());
    COUNTING.store(false, Ordering::Relaxed);

    received.expect("receive second Initial");
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0, "warm Retry");
    let outgoing = mux.output().drain().next().expect("second Retry");
    assert!(matches!(&outgoing, Outgoing::Suffix(..)));
    assert_eq!(outgoing.payload().as_ptr(), allocation);

    let options = conn::config::Options {
        stateless_reset_secret: Some([0x5a; 32]),
        ..Default::default()
    };
    let signing = SigningKey::from_seed(&[0x49; 32]).expect("reset signing key");
    let mut reset_mux =
        dope_quic::mux::setup::Server::accept(Noop, signing, options).expect("reset server setup");
    let mut trigger = vec![0x40; 64];

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let received = reset_mux
        .protocol()
        .recv(source, &mut trigger, Instant::now());
    COUNTING.store(false, Ordering::Relaxed);

    received.expect("receive unknown packet");
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        1,
        "cold stateless reset"
    );
    let outgoing = reset_mux.output().drain().next().expect("one reset");
    assert!(matches!(&outgoing, Outgoing::Plain(..)));
    let allocation = outgoing.payload().as_ptr();
    reset_mux.output().recycle(outgoing);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let received = reset_mux
        .protocol()
        .recv(source, &mut trigger, Instant::now());
    COUNTING.store(false, Ordering::Relaxed);

    received.expect("receive second unknown packet");
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "warm stateless reset"
    );
    let outgoing = reset_mux.output().drain().next().expect("second reset");
    assert!(matches!(&outgoing, Outgoing::Plain(..)));
    assert_eq!(outgoing.payload().as_ptr(), allocation);
}
