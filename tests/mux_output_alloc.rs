pub mod common;
use common::suite::mux::output::{CLIENT, Pair, SERVER, Seen};
use dope_quic::conn::Epoch;
use dope_quic::proto::epoch;
use dope_test::alloc::Tracker;
use std::pin::Pin;
use std::time::Duration;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn cid_rotation_alloc_free() {
    let Pair {
        mut client,
        mut server,
        mut now,
        ..
    } = Seen::try_pair(false, 1).expect("output fixture must establish");
    let id = server
        .sole()
        .expect("the one-connection fixture must expose its server handle");

    now = Seen::rotate_cid(&mut client, &mut server, id, now).expect("output rotate_cid");

    let span = Tracker::begin();
    Seen::rotate_cid(&mut client, &mut server, id, now + Duration::from_secs(1))
        .expect("output rotate_cid");
    let activity = span.finish();

    assert_eq!(activity.allocations, 0);
}

#[test]
fn ack_keeps_safe_wake() {
    let Pair {
        mut client,
        mut server,
        handles,
        mut now,
    } = Seen::try_pair(false, 1).expect("output fixture must establish");
    let [handle]: &[_; 1] = handles
        .as_slice()
        .try_into()
        .expect("single connection fixture must retain exactly one handle");
    let handle = *handle;

    Seen::enqueue(&mut client, handle, 1, 1_150, now).expect("output enqueue");
    assert!(Seen::pump(&mut client, &mut server, CLIENT, now).is_ok());
    now += Duration::from_millis(30);
    assert!(Seen::pump(&mut server, &mut client, SERVER, now).is_ok());

    let safe = Pin::new(&mut client)
        .observe(now, |turn| turn.deadline())
        .expect("ACK retirement must retain the earlier safe mux wake");
    let timer = client
        .conn(handle)
        .and_then(|conn| conn.view().recovery().next_timer())
        .expect("the acknowledged fixture connection must retain its idle timer");
    assert!(
        safe < timer,
        "ACK retirement should retain the earlier indexed wake instead of rewriting the heap"
    );

    let wake = safe + Duration::from_micros(1);
    Pin::new(&mut client).observe(wake, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture mux connection must admit safe-wake output"
        )
    });
    assert_eq!(client.active_conns(), 1);
    assert_eq!(
        Pin::new(&mut client).observe(wake, |turn| turn.deadline()),
        Some(timer)
    );
}

#[test]
fn pto_replaces_deadline() {
    let Pair {
        mut client,
        handles,
        now,
        ..
    } = Seen::try_pair(false, 1).expect("output fixture must establish");
    let [handle]: &[_; 1] = handles
        .as_slice()
        .try_into()
        .expect("single connection fixture must retain exactly one handle");
    let handle = *handle;

    Seen::enqueue(&mut client, handle, 1, 1_150, now).expect("output enqueue");
    let dropped = Seen::take_one(&mut client, now)
        .expect("output take_one")
        .expect("the enqueued payload must produce one mux flight");
    Pin::new(&mut client).output().recycle(dropped);

    let pto = client
        .conn(handle)
        .and_then(|conn| conn.view().recovery().next_timer())
        .expect("a dropped application packet must arm its PTO timer");
    let fired_at = pto + Duration::from_nanos(1);
    Pin::new(&mut client).observe(fired_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture mux connection must admit PTO output"
        )
    });
    loop {
        let probe =
            Pin::new(&mut client).observe(fired_at, |mut turn| turn.output().drain().next());
        let Some(probe) = probe else {
            break;
        };
        Pin::new(&mut client).output().recycle(probe);
    }

    let next = Pin::new(&mut client)
        .observe(fired_at, |turn| turn.deadline())
        .expect("in-flight PTO probes retain a future deadline");
    assert!(
        next > fired_at,
        "consuming PTO must replace, not retain, its expired heap key"
    );
}

#[test]
fn pacing_releases_output() {
    let Pair {
        mut client,
        handles,
        now,
        ..
    } = Seen::try_pair(false, 1).expect("output fixture must establish");
    let [handle]: &[_; 1] = handles
        .as_slice()
        .try_into()
        .expect("single connection fixture must retain exactly one handle");
    let handle = *handle;

    const PACKETS: usize = 32;
    Seen::enqueue(&mut client, handle, PACKETS, 1_150, now).expect("output enqueue");
    let initial = Pin::new(&mut client).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture mux connection must admit the initial paced burst"
        );
        turn.output().drain().collect::<Vec<_>>()
    });
    let sent = Seen::packet_count(&initial);
    assert!(
        (1..PACKETS).contains(&sent),
        "the initial pacer burst emitted {sent} of {PACKETS} packets"
    );
    for outgoing in initial {
        Pin::new(&mut client).output().recycle(outgoing);
    }

    let due = Pin::new(&mut client)
        .observe(now, |turn| turn.deadline())
        .expect("the pending packet owns a pacing deadline");
    assert!(due > now);
    assert!(
        Pin::new(&mut client).observe(due - Duration::from_nanos(1), |mut turn| {
            assert!(
                turn.output().drive().is_ok(),
                "fixture mux connection must remain admissible before pacing release"
            );
            turn.output().drain().next().is_none()
        })
    );
    let released = Pin::new(&mut client).observe(due, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture mux connection must admit pacing release output"
        );
        turn.output().drain().collect::<Vec<_>>()
    });
    assert_eq!(Seen::packet_count(&released), 1);
    for outgoing in released {
        Pin::new(&mut client).output().recycle(outgoing);
    }
}

#[test]
fn ack_debt_tracks_deadline() {
    let Pair {
        mut client,
        mut server,
        handles,
        mut now,
    } = Seen::try_pair(false, 1).expect("output fixture must establish");
    let [local_id]: &[_; 1] = handles
        .as_slice()
        .try_into()
        .expect("single connection fixture must retain exactly one handle");
    let local_id = *local_id;
    let peer_id = server
        .sole()
        .expect("the one-connection fixture must expose its server handle");

    for _ in 0..4 {
        now += Duration::from_millis(30);
        assert!(Seen::pump(&mut client, &mut server, CLIENT, now).is_ok());
        assert!(Seen::pump(&mut server, &mut client, SERVER, now).is_ok());
    }
    Pin::new(&mut client).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connection must admit settled output"
        )
    });
    Pin::new(&mut server).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture server connection must admit settled output"
        )
    });

    Seen::enqueue(&mut server, peer_id, 1, 1_150, now).expect("output enqueue");
    assert!(Seen::pump(&mut server, &mut client, SERVER, now).is_ok());
    assert_eq!(
        server
            .conn(peer_id)
            .map(|peer| peer.view().recovery().unacked(Epoch::Application)),
        Some(1)
    );
    assert!(Pin::new(&mut client).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connection must remain admissible before delayed ACK"
        );
        turn.output().drain().next().is_none()
    }));

    let due = Pin::new(&mut client)
        .observe(now, |turn| turn.deadline())
        .expect("one received application packet must arm its delayed ACK deadline");
    assert!(due > now && due <= now + Duration::from_millis(25));
    assert!(
        Pin::new(&mut client).observe(due - Duration::from_nanos(1), |mut turn| {
            assert!(
                turn.output().drive().is_ok(),
                "fixture client connection must remain admissible before ACK deadline"
            );
            turn.output().drain().next().is_none()
        })
    );

    let mut acks = Pin::new(&mut client).observe(due, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connection must admit its delayed ACK"
        );
        turn.output().drain().collect::<Vec<_>>()
    });
    assert_eq!(Seen::packet_count(&acks), 1);
    for outgoing in &mut acks {
        for packet in outgoing.segments_mut() {
            assert!(
                Pin::new(&mut server)
                    .observe(due, |mut turn| {
                        turn.protocol().recv(CLIENT, packet, epoch::WALL_CLOCK)
                    })
                    .is_ok(),
                "a delayed ACK emitted by the client must pass server mux ingress"
            );
            assert_eq!(server.handler().certificates, 0);
        }
    }
    for outgoing in acks {
        Pin::new(&mut client).output().recycle(outgoing);
    }
    assert_eq!(
        server
            .conn(peer_id)
            .map(|peer| peer.view().recovery().unacked(Epoch::Application)),
        Some(0)
    );

    let next = Pin::new(&mut client)
        .observe(due, |turn| turn.deadline())
        .expect("the ACKed fixture connection must retain an idle or recovery deadline");
    assert!(next > due);
    assert!(client.conn(local_id).is_some());
}
