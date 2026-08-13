#[test]
fn bounded_control_lifecycle_preserves_deferred_and_generation_owned_work() {
    use crate::conn::delivery::{Control, Handle};
    use crate::conn::{self, control, journal};
    use crate::frame::ack_ranges;
    use control::{delivery, kind};

    fn packet(pn: u64) -> journal::Packet {
        use std::time::Instant;

        journal::Packet {
            epoch: conn::Epoch::Application,
            pn,
            sent_time: Instant::now(),
            bytes_sent: 32,
            transmission: journal::Transmission::new(false, true, true),
            crypto: None,
        }
    }

    fn track(journals: &mut journal::Table, pn: u64, handle: Handle<Control>) {
        let key = journals
            .insert(packet(pn))
            .expect("journal packet capacity");
        assert!(journals.push_control(key, handle));
    }

    fn suffix(pending: &control::Pending) -> (Handle<Control>, Control) {
        pending
            .ready()
            .suffix()
            .expect("one suffix lane is ready")
            .next()
            .expect("one control is ready")
    }

    let mut pending = control::Pending::new(1);
    let mut maximum = None;
    control::Write::queue_max_data(&mut pending, &mut maximum, 10);
    let first_owner = maximum.expect("MAX_DATA owns the only slot");
    assert!(control::Write::owner_is_live(&pending, Some(first_owner)));

    let mut reset = control::Signal::<kind::ResetStream>::new();
    control::Write::queue_reset_stream(&mut pending, &mut reset, 7, 11, 0);
    assert_eq!(reset.deferred(), Some(11));
    assert!(control::Write::owner_is_live(&pending, Some(first_owner)));

    let (original, record) = suffix(&pending);
    assert_eq!(record, Control::MaxData(10));
    let committed = delivery::Delivery::new(&mut pending)
        .commit(conn::Epoch::Application, record, original)
        .expect("selected control commits");

    let mut journals = journal::Table::new(4, 4, 0);
    track(&mut journals, 0, committed);

    pending.arm_probes(conn::Epoch::Application);
    let (probe, probe_record) = pending
        .next_probe(conn::Epoch::Application, |_| false)
        .expect("in-flight control is PTO-probe eligible");
    assert_eq!(probe, committed);
    assert_eq!(probe_record, record);
    let probe = delivery::Delivery::new(&mut pending)
        .commit(conn::Epoch::Application, probe_record, probe)
        .expect("PTO adds a second carrier without a second owner");
    track(&mut journals, 1, probe);

    journals.drain_where(
        |packet| packet.pn == 0,
        |_, controls, mut streams| {
            assert!(streams.next().is_none());
            for handle in controls {
                control::Write::lose_control(&mut pending, handle);
            }
        },
    );
    assert_eq!(journals.count_epoch(conn::Epoch::Application), 1);
    assert!(control::Write::owner_is_live(&pending, Some(first_owner)));
    assert!(!pending.ready().has_sendable());

    journals.drain_ack(
        conn::Epoch::Application,
        1,
        0,
        ack_ranges::Ranges::new(&[], 0),
        |_, controls, mut streams| {
            assert!(streams.next().is_none());
            for handle in controls {
                assert!(matches!(
                    control::Write::acknowledge_control(&mut pending, handle),
                    control::Effect::None
                ));
            }
        },
    );
    assert_eq!(journals.count_epoch(conn::Epoch::Application), 0);
    assert!(!control::Write::owner_is_live(&pending, Some(first_owner)));
    assert_eq!(pending.remaining_capacity(), 1);

    control::Write::lose_control(&mut pending, original);
    assert!(matches!(
        control::Write::acknowledge_control(&mut pending, original),
        control::Effect::None
    ));

    {
        let mut permit = pending.try_reserve(1).expect("ACK returned capacity");
        control::Write::queue_reset_stream(&mut permit, &mut reset, 7, 11, 0);
    }
    let reset_owner = reset.owner().expect("deferred reset materialized");
    assert!(control::Write::owner_is_live(&pending, Some(reset_owner)));
    assert!(!reset.is_deferred());

    let (reset_handle, reset_record) = suffix(&pending);
    assert_eq!(reset_record, Control::ResetStream(7, 11, 0));
    let reset_handle = delivery::Delivery::new(&mut pending)
        .commit(conn::Epoch::Application, reset_record, reset_handle)
        .expect("materialized reset commits");
    track(&mut journals, 2, reset_handle);
    journals.drain_ack(
        conn::Epoch::Application,
        2,
        0,
        ack_ranges::Ranges::new(&[], 0),
        |_, controls, _| {
            for handle in controls {
                assert!(matches!(
                    control::Write::acknowledge_control(&mut pending, handle),
                    control::Effect::RetireStream(7)
                ));
            }
        },
    );
    assert!(!control::Write::owner_is_live(&pending, Some(reset_owner)));

    control::Write::queue_reset_stream(&mut pending, &mut reset, 7, 12, 0);
    assert_eq!(reset.deferred(), Some(12));
    {
        let mut permit = pending.try_reserve(1).expect("retired slot is reusable");
        control::Write::queue_reset_stream(&mut permit, &mut reset, 7, 12, 0);
    }
    let replacement_owner = reset.owner().expect("updated reset owns the recycled slot");
    assert_ne!(replacement_owner.0, reset_owner.0);
    assert!(control::Write::owner_is_live(
        &pending,
        Some(replacement_owner)
    ));

    assert!(matches!(
        control::Write::acknowledge_control(&mut pending, reset_handle),
        control::Effect::None
    ));
    assert!(control::Write::owner_is_live(
        &pending,
        Some(replacement_owner)
    ));
}
