pub mod common;

use std::time::{Duration, Instant};

use common::peer;
use common::suite::peers::config;
use dope_quic::conn::{self, output::transmit, wire::packet::Batch};
use dope_test::alloc::Tracker;
use o3::alloc;
use peer::{Pair, Receiver as _};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn control_stream_retry() {
    use o3::depot::capacity;
    use peer::Scope as _;

    const TOKEN: [u8; 8] = [0x7b; 8];
    let mut observed = false;
    for budget in 0..32 {
        let Pair {
            mut client,
            mut server,
            mut work,
        } = config::try_packet().expect("established packet pair");
        let stream = {
            let mut send = client.send_streams();
            let stream = send.open_uni().expect("stream credit");
            send.send(stream, &[0x5a; 32]).expect("payload credit");
            send.finish(stream).expect("stream FIN");
            stream
        };
        client
            .with_scope(|mut scope| scope.path().try_probe(TOKEN))
            .expect("path challenge");
        let now = client
            .view()
            .recovery()
            .send_at(Instant::now() + Duration::from_secs(1));
        let before = client.view().recovery().in_flight();
        let mut batch = Batch::default();
        let result = Tracker::fail_after(budget, || {
            client.with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
        });
        if !matches!(
            result,
            Err(transmit::Error::Admission(transmit::Admission::Packet {
                space: conn::Epoch::Application,
                reason: capacity::Reason::Allocation(alloc::Error::Exhausted),
                controls,
                streams,
                ..
            })) if controls.get() > 0 && streams.get() > 0
        ) {
            continue;
        }
        assert!(batch.is_empty(), "joint admission must publish no packet");
        assert_eq!(client.view().recovery().in_flight(), before);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
            .expect("retry retains both selections");
        assert_eq!(batch.packets(), 1);
        let next = client.view().recovery().send_at(now);
        assert!(
            next < client
                .view()
                .recovery()
                .next_timer()
                .expect("retry arms PTO")
        );
        let mut idle = Batch::default();
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut idle, next, 1, 1200))
            .expect("completed selections leave no stale packet");
        assert!(idle.is_empty());
        for wire in batch.iter_mut() {
            server
                .receive(&mut work, wire, now)
                .expect("retry authenticates");
        }
        assert_eq!(
            server
                .recv()
                .recv_owned(stream.id())
                .expect("stream payload"),
            Some(vec![0x5a; 32])
        );
        assert!(
            server
                .stream_state()
                .recv_eof(stream.id())
                .expect("stream FIN")
        );
        assert!(
            server
                .recv()
                .recv_owned(stream.id())
                .expect("drained stream")
                .is_none()
        );
        client
            .receive_from(&mut work, &mut server, next)
            .expect("challenge response");
        assert!(client.view().path().has_token(&TOKEN));
        observed = true;
        break;
    }
    assert!(observed, "no joint packet allocation failure observed");
}
