use crate::common::peer;
pub mod common;
use std::{
    mem,
    time::{Duration, Instant},
};

use dope_quic::conn::wire::packet::Batch;
use dope_test::alloc::Tracker;
use peer::{Pair, Receiver as _, warm::control::Batches};

#[test]
fn recurring() {
    let pair = Pair::try_default();
    let mut client = pair.expect("test precondition").client;
    let mut batch = Batch::default();
    let now = Instant::now() + Duration::from_secs(20);

    let sample = Tracker::begin();
    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(1u64.to_ne_bytes())),
        Ok(())
    );
    let activity = sample.finish();

    assert_eq!(
        activity.allocations, 0,
        "first control owner allocation size {}",
        activity.allocated_bytes
    );

    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
        .expect("warmed client journals must admit recurring control output");
    assert_eq!(batch.packets(), 1);

    let sample = Tracker::begin();
    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(2u64.to_ne_bytes())),
        Ok(())
    );
    client
        .with_scope(|mut scope| {
            scope
                .output()
                .send_batch(&mut batch, now + Duration::from_millis(1), 1, 1200)
        })
        .expect("warmed client journals must admit repeated control output");
    let activity = sample.finish();

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        activity.allocations, 0,
        "recurring control allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn pto() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let token = 3u64.to_ne_bytes();
    let mut batch = Batch::default();
    let sent_at = Instant::now() + Duration::from_secs(20);

    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(token)),
        Ok(())
    );
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 2, 1200))
        .expect("warmed client journals must admit the control flight");
    assert!(!batch.is_empty());
    let deadline = client
        .view()
        .recovery()
        .next_timer()
        .expect("unacknowledged path challenge must arm control PTO");
    let probe_at = deadline + Duration::from_millis(1);

    let sample = Tracker::begin();
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, probe_at, 2, 1200))
        .expect("warmed client journals must admit the control PTO");
    let activity = sample.finish();

    assert!(!batch.is_empty());
    assert_eq!(
        activity.allocations, 0,
        "control PTO allocation size {}",
        activity.allocated_bytes
    );

    server
        .receive_all(&mut work, &mut batch, probe_at)
        .expect("control PTO probe must pass server ingress");
    client
        .receive_from(&mut work, &mut server, probe_at)
        .expect("control PTO response must pass client ingress");
    assert!(client.view().path().has_token(&token));
}

#[test]
fn delayed_ack() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let mut batches = Batches::default();
    let mut sent_at = Instant::now() + Duration::from_secs(30);
    for round in 0..3 {
        let first = (4_u64 + round * 2).to_ne_bytes();
        let next = (5_u64 + round * 2).to_ne_bytes();
        let sample = (round != 0).then(Tracker::begin);
        assert_eq!(
            client.with_scope(|mut scope| scope.path().try_probe(first)),
            Ok(())
        );
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.original, sent_at, 4, 1_200)
            })
            .expect("warmed client journals must admit the original challenge");
        assert!(!batches.original.is_empty());
        server
            .receive_all(&mut work, &mut batches.original, sent_at)
            .expect("original path challenge must pass server ingress");

        let ack_at = server
            .view()
            .recovery()
            .send_at(sent_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.first_ack, ack_at, 4, 1_200)
            })
            .expect("warmed server journals must admit the first challenge response");
        assert!(!batches.first_ack.is_empty());

        let deadline = client
            .view()
            .recovery()
            .next_timer()
            .expect("unacknowledged path challenge must arm control PTO");
        let probe_at = deadline + Duration::from_millis(1);
        assert_eq!(
            client.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
            Ok(())
        );
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.probe, probe_at, 4, 1_200)
            })
            .expect("warmed client journals must admit the challenge probe");
        assert!(!batches.probe.is_empty());
        server
            .receive_all(&mut work, &mut batches.probe, probe_at)
            .expect("path challenge probe must pass server ingress");

        let late_at = server
            .view()
            .recovery()
            .send_at(probe_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.late_probe_ack, late_at, 4, 1_200)
            })
            .expect("warmed server journals must admit the late probe response");
        assert!(!batches.late_probe_ack.is_empty());

        let retire = late_at + Duration::from_millis(1);
        client
            .receive_all(&mut work, &mut batches.first_ack, retire)
            .expect("first response must retire the original challenge");
        assert!(client.view().path().has_token(&first));

        assert_eq!(
            client.with_scope(|mut scope| scope.path().try_probe(next)),
            Ok(())
        );
        let next_at = client
            .view()
            .recovery()
            .send_at(retire + Duration::from_millis(1));
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.replacement, next_at, 4, 1_200)
            })
            .expect("warmed client journals must admit the replacement challenge");
        assert!(!batches.replacement.is_empty());

        client
            .receive_all(&mut work, &mut batches.late_probe_ack, next_at)
            .expect("late probe response must pass client ingress");
        assert!(!client.view().path().has_token(&next));

        server
            .receive_all(&mut work, &mut batches.replacement, next_at)
            .expect("replacement path challenge must pass server ingress");
        let reply_at = server
            .view()
            .recovery()
            .send_at(next_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.replacement_response, reply_at, 4, 1_200)
            })
            .expect("warmed server journals must admit the replacement response");
        assert!(!batches.replacement_response.is_empty());
        client
            .receive_all(&mut work, &mut batches.replacement_response, reply_at)
            .expect("replacement response must pass client ingress");
        assert!(client.view().path().has_token(&next));

        let final_at = client
            .view()
            .recovery()
            .send_at(reply_at + Duration::from_millis(1));
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.final_ack, final_at, 4, 1_200)
            })
            .expect("warmed client journals must admit the final acknowledgement");
        server
            .receive_all(&mut work, &mut batches.final_ack, final_at)
            .expect("final response acknowledgement must pass server ingress");
        assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
        if let Some(sample) = sample {
            let activity = sample.finish();
            if round == 1 {
                assert_eq!(activity.allocations, 1);
                assert_eq!(activity.allocated_bytes, 64 * mem::size_of::<[u8; 8]>());
            } else {
                assert_eq!(
                    activity.allocations, 0,
                    "delayed-ACK control reuse allocation size {}",
                    activity.allocated_bytes
                );
            }
        }
        sent_at = final_at + Duration::from_secs(1);
    }
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
