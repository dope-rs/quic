pub mod common;

use common::{
    peer,
    suite::mux::{
        Reject,
        dispatch::{CLIENT, Capture},
        install,
    },
};
use dope_quic::{
    conn::{self, life::options::Options},
    errors,
    runtime::mux::builder::Plan,
    security::crypto,
};
use dope_test::alloc::Tracker;
use std::{pin::Pin, time::Instant};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn reject_reuses_slot() {
    drop(install::server().expect("initialize native configuration"));

    let (_, total) = Tracker::activity(|| {
        let (key, _) = peer::raw(0x7a).expect("server identity");
        let mut mux = Capture::server(
            Reject {
                attempts: Vec::with_capacity(2),
                closed: Vec::with_capacity(1),
                certificates: 0,
            },
            key.server().expect("server TLS"),
            Options::default(),
            Plan::try_new(1, 8, 16 << 10).expect("one connection slot"),
        )
        .expect("server mux");
        let now = Instant::now();
        let initial = install::initial(&[0x31; 8], &[0x42; 8]).expect("Initial");
        let mut packet = initial.clone();
        let (result, rejected) =
            Tracker::activity(|| Capture::recv(&mut mux, CLIENT, &mut packet, now));
        assert!(matches!(result, Err(errors::Receive::ApplicationRejected)));
        assert_eq!(rejected.allocations, rejected.deallocations);
        assert_eq!(rejected.allocated_bytes, rejected.deallocated_bytes);
        assert_eq!(mux.active_conns(), 0);
        assert!(mux.handler().closed.is_empty());
        let first = mux.handler().attempts[0];
        assert!(mux.conn(first).is_none());

        packet.copy_from_slice(&initial);
        assert!(matches!(
            Capture::recv(&mut mux, CLIENT, &mut packet, now),
            Err(errors::Receive::Packet(conn::Error::Crypto(
                crypto::Error::Decrypt(rustls::Error::DecryptError)
            )))
        ));
        let second = mux.sole().expect("rejected slot is reusable");
        assert_eq!(second.index(), first.index());
        assert_eq!(second.generation(), first.generation() + 1);
        assert_eq!(mux.handler().attempts, [first, second]);
        assert!(mux.conn(first).is_none());
        assert_eq!(
            Pin::new(&mut mux).observe(now, |mut turn| turn.protocol().try_close(second)),
            Ok(())
        );
        assert_eq!(
            Pin::new(&mut mux).observe(now, |mut turn| turn.protocol().try_close(second)),
            Err(errors::Access::InvalidHandle)
        );
        assert!(matches!(
            mux.handler().closed.as_slice(),
            [(closed, app)] if *closed == second && app == b"connection"
        ));
        assert_eq!(mux.handler().certificates, 0);
    });
    assert_eq!(total.allocations, total.deallocations);
    assert_eq!(total.allocated_bytes, total.deallocated_bytes);
}
