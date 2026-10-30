use dope_quic::wire::{frame, varint};
use dope_test::alloc::Tracker;
use frame::decode::error::{Error, Fault};
use o3::alloc;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn owned_alloc_fails() {
    let cases: &[(&[u8], usize, bool)] = &[
        (&[frame::TYPE_CRYPTO, 0, 1, 0x42], 0, false),
        (&[frame::TYPE_ACK, 2, 0, 1, 0, 0, 0], 0, false),
        (&[frame::TYPE_CRYPTO, 0, 1, 0x42], 1, true),
    ];
    for &(wire, allows, list) in cases {
        let (result, activity) = Tracker::activity(|| {
            Tracker::fail_after(allows, || {
                if list {
                    frame::Frame::decode_all(wire).map(drop)
                } else {
                    frame::Frame::decode(wire).map(drop)
                }
            })
        });
        assert_eq!(result, Err(Error::Allocation(alloc::Error::Exhausted)));
        assert_eq!(activity.allocations, allows);
        assert_eq!(activity.allocations, activity.deallocations);
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);

        let (retry, activity) = Tracker::activity(|| {
            if list {
                frame::Frame::decode_all(wire).map(drop)
            } else {
                frame::Frame::decode(wire).map(drop)
            }
        });
        retry.expect("same frame retries after allocation failure");
        assert_eq!(activity.allocations, activity.deallocations);
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }
}

#[test]
fn ecn_alloc_before_fault() {
    let wire = [frame::TYPE_ACK_ECN, 2, 0, 1, 0, 0, 0];
    let (result, activity) =
        Tracker::activity(|| Tracker::fail_after(0, || frame::Frame::decode(&wire).map(drop)));
    assert_eq!(result, Err(Error::Allocation(alloc::Error::Exhausted)));
    assert_eq!(activity, dope_test::alloc::Activity::default());

    let (result, activity) = Tracker::activity(|| frame::Frame::decode(&wire).map(drop));
    assert_eq!(
        result,
        Err(Error::Fault(Fault::VarInt {
            offset: 7,
            source: varint::Error::Underflow {
                actual: 0,
                required: 1,
            },
        }))
    );
    assert_eq!(activity.allocations, 1);
    assert_eq!(activity.deallocations, 1);
    assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
}
