use crate::common::peer;
use common::suite::peers::config::Parameters as _;
pub mod common;
use dope_quic::conn::life::options::Options;
use std::time::{Duration, Instant};

use dope_quic::conn::output::transmit;
use dope_quic::errors::Code;
use dope_test::alloc::Tracker;
use peer::Bind as _;
use peer::Event;
use peer::Scope as _;
use peer::flight::Flight;
use peer::{Pair, Receiver as _, warm::receive::Batches};

/// Complete the STOP/RESET ACK edge even when compact headers coalesce controls.
#[test]
fn delayed_ack() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(
        Options::try_recv().expect("fixture configuration bounds"),
        Options::try_recv().expect("fixture configuration bounds"),
    )
    .expect("test precondition");
    let mut batches = Batches::default();
    let mut received = Vec::with_capacity(129);
    let mut sent_at = Instant::now() + Duration::from_secs(8);
    for round in 0..3 {
        let sample = (round == 2).then(Tracker::begin);
        let victim = client
            .send_streams()
            .open_uni()
            .expect("victim send-stream slot must be available");
        let anchor = client
            .send_streams()
            .open_uni()
            .expect("anchor send-stream slot must be available");
        let srv_vic = victim.bind(&server).expect("peer stream must resolve");
        let srv_anc = anchor.bind(&server).expect("peer stream must resolve");
        client
            .send_streams()
            .send(victim, &[0x71; 64])
            .expect("victim stream credit must admit its payload");
        client
            .send_streams()
            .send(anchor, &[0x72; 64])
            .expect("anchor stream credit must admit its payload");
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.initial, sent_at, 4, 1_200)
            })
            .expect("warmed client journals must admit initial stream packets");
        assert!(!batches.initial.is_empty());
        server
            .receive_all(&mut work, &mut batches.initial, sent_at)
            .expect("initial stream packet must pass server ingress");

        received.clear();
        received.push(0);
        assert_eq!(server.recv().recv(srv_vic, &mut received), Ok(64));
        assert!(received[1..].iter().all(|&byte| byte == 0x71));

        let ctrl_at = server
            .view()
            .recovery()
            .send_at(sent_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.old_control, ctrl_at, 1, 1_200)
            })
            .expect("warmed server journals must admit old receive control");
        assert!(!batches.old_control.is_empty());
        client
            .receive_all(&mut work, &mut batches.old_control, ctrl_at)
            .expect("old receive control must pass client ingress");

        let delay = Duration::from_millis(u64::from(
            server
                .view()
                .peer()
                .params()
                .expect("client transport parameters")
                .timing()
                .ack_ms(),
        ));
        let old_at = client.view().recovery().send_at(ctrl_at + delay);
        let old_ack = Flight::emit_at(&mut client, &mut batches.delayed_old_ack, old_at, 1, 1_200)
            .expect("pre-admitted old ACK journals must accept the flight");
        assert!(!old_ack.is_empty());

        client
            .send_streams()
            .reset(victim, Code::from_u8(0x73))
            .expect("victim send stream must reset once");
        let reset_at = old_at + Duration::from_millis(1);
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.reset, reset_at, 1, 1_200)
            })
            .expect("warmed client journals must admit the stream reset");
        assert!(!batches.reset.is_empty());
        server
            .recv()
            .stop(srv_vic, Code::from_u8(0x74))
            .expect("victim receive stream must stop once");
        let loss_at = server
            .view()
            .recovery()
            .next_timer()
            .expect("unacknowledged receive control must arm PTO")
            + Duration::from_millis(1);
        assert_eq!(
            server.with_scope(|mut scope| scope.recovery().try_loss(loss_at)),
            Ok(())
        );
        server
            .receive_all(&mut work, &mut batches.reset, loss_at)
            .expect("victim reset must pass server ingress");

        let free_at = server
            .view()
            .recovery()
            .send_at(loss_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.reset_ack_and_probe, free_at, 2, 1_200)
            })
            .expect("warmed server journals must admit the reset acknowledgement and probe");
        assert!(!batches.reset_ack_and_probe.is_empty());
        client
            .receive_all(&mut work, &mut batches.reset_ack_and_probe, free_at)
            .expect("reset acknowledgement and probe must pass client ingress");
        assert!(server.poll().poll_event() == Some(Event::Readable { stream_id: srv_anc }));
        assert!(
            server.poll().poll_event()
                == Some(Event::Reset {
                    stream_id: srv_vic,
                    error_code: dope_quic::errors::Code::from_u8(0x73),
                })
        );
        let ack_at = client
            .view()
            .recovery()
            .send_at(free_at + Duration::from_millis(1));
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.release_ack, ack_at, 2, 1_200)
            })
            .expect("warmed client journals must admit the release acknowledgement");
        server
            .receive_all(&mut work, &mut batches.release_ack, ack_at)
            .expect("release acknowledgement must pass server ingress");

        let limit_at = server
            .view()
            .recovery()
            .send_at(ack_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.reset_ack_and_probe, limit_at, 2, 1_200)
            })
            .expect("warmed server journals must admit the stream limit update");
        client
            .receive_all(&mut work, &mut batches.reset_ack_and_probe, limit_at)
            .expect("stream limit update must pass client ingress");

        let next = client
            .send_streams()
            .open_uni()
            .expect("released victim slot must admit a replacement stream");
        let srv_next = next.bind(&server).expect("peer stream must resolve");
        client
            .send_streams()
            .send(next, &[0x75; 64])
            .expect("replacement stream credit must admit its first payload");
        let flight = Flight::emit_due(
            &mut client,
            &mut batches.replacement.first,
            limit_at + Duration::from_millis(1),
            1,
            1_200,
        )
        .expect("pre-admitted replacement journals must accept the flight");
        let next_at = flight.sent_at();
        assert!(
            flight.effects().contains(transmit::Effects::FRESH_STREAM),
            "replacement flight did not commit a fresh STREAM range",
        );
        flight
            .deliver(&mut work, &mut server)
            .expect("replacement flight must reach its peer");

        received.clear();
        received.push(0);
        assert_eq!(server.recv().recv(srv_next, &mut received), Ok(64));
        assert!(received[1..].iter().all(|&byte| byte == 0x75));
        let late_at = next_at + Duration::from_millis(1);
        old_ack
            .deliver_at(&mut work, &mut server, late_at)
            .expect("delayed acknowledgment must reach its peer after emission");

        let grant_at = server
            .view()
            .recovery()
            .send_at(late_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.replacement.credit, grant_at, 1, 1_200)
            })
            .expect("warmed server journals must admit replacement stream credit");
        assert!(!batches.replacement.credit.is_empty());
        client
            .receive_all(&mut work, &mut batches.replacement.credit, grant_at)
            .expect("replacement stream credit must pass client ingress");

        client
            .send_streams()
            .send(next, &[0x75; 64])
            .expect("replacement stream credit must admit its second payload");
        client
            .send_streams()
            .finish(next)
            .expect("replacement send stream must finish once");
        client
            .send_streams()
            .finish(anchor)
            .expect("anchor send stream must finish once");
        let mut done = grant_at;
        for turn in 1..=16 {
            done = batches
                .drain
                .try_exchange(
                    &mut client,
                    &mut server,
                    &mut work,
                    grant_at + Duration::from_millis(turn * 10),
                )
                .expect("drain flight");
        }
        assert_eq!(server.recv().recv(srv_next, &mut received), Ok(64));
        assert_eq!(received.len(), 129);
        assert!(received[1..].iter().all(|&byte| byte == 0x75));
        received.clear();
        received.push(0);
        assert_eq!(server.recv().recv(srv_anc, &mut received), Ok(64));
        assert_eq!(received[1..], [0x72; 64]);
        assert!(
            server
                .stream_state()
                .recv_eof(srv_next)
                .expect("replacement receive stream must retain state")
        );
        assert!(
            server
                .stream_state()
                .recv_eof(srv_anc)
                .expect("anchor receive stream must retain state")
        );
        assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
        if let Some(sample) = sample {
            let activity = sample.finish();
            assert_eq!(
                activity.allocations, 0,
                "delayed-ACK receive-schedule reuse allocation size {}",
                activity.allocated_bytes
            );
            break;
        }

        let fill_at = server
            .view()
            .recovery()
            .send_at(done + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.drain.server, fill_at, 4, 1_200)
            })
            .expect("warmed server journals must admit replenished stream credit");
        assert!(!batches.drain.server.is_empty());
        client
            .receive_all(&mut work, &mut batches.drain.server, fill_at)
            .expect("replenished stream credit must pass client ingress");
        let ack_at = client
            .view()
            .recovery()
            .send_at(fill_at + Duration::from_millis(1));
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.drain.client, ack_at, 4, 1_200)
            })
            .expect("warmed client journals must admit the replenishment acknowledgement");
        server
            .receive_all(&mut work, &mut batches.drain.client, ack_at)
            .expect("replenishment acknowledgement must pass server ingress");
        assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
        sent_at = ack_at + Duration::from_secs(1);
    }
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
