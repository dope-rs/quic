pub mod common;
use common::receive::retained::{
    Proof,
    run::{CLIENT_ROUTE, ENDPOINT, Error, SERVER_ROUTE, mode, pooled},
};
use common::recovery;
use dope::core::driver::life::recovery::Recovery;
use dope::core::{driver::route::Id, io::Reclaimed};
use dope_quic::stream::Capacity;
use dope_test::alloc::Tracker;
use o3::alloc;
use std::{array, convert::Infallible, rc::Rc};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

fn recover(failure: Recovery<'_, '_>) -> Infallible {
    panic!("native recovery: {:?}", failure.cause())
}

fn complete<T>(result: Result<T, Error<'_, '_>>) -> T {
    assert!(
        result.is_ok(),
        "{}",
        match &result {
            Err(Error::Create(cause)) => format!("executor creation: {:?}", cause.kind()),
            Err(Error::Domain(cause)) => format!("domain finalization: {:?}", cause.cause()),
            Err(Error::Stage(cause)) => format!("session: {cause:?}"),
            Err(Error::Setup(cause)) => format!("pooled reuse: {cause:?}"),
            Err(Error::Observers(proof)) => format!(
                "fixture observers still retained: {}",
                Rc::strong_count(proof)
            ),
            Ok(_) => String::new(),
        }
    );
    result.ok().expect("fixture completion")
}

fn verify((proof, reports): (Proof, Vec<Reclaimed>), fail: bool) -> (Vec<u8>, usize) {
    recovery::Teardown::new([Id::fixed::<SERVER_ROUTE>(), Id::fixed::<CLIENT_ROUTE>()])
        .verify(reports)
        .expect("both endpoint receive operations must retire exactly once");
    assert!(proof.failures.packet.is_none(), "{:?}", proof.failures);
    assert!(proof.failures.detail.is_none(), "{:?}", proof.failures);
    assert!(proof.failures.fixture.is_none(), "{:?}", proof.failures);
    assert!(proof.failures.shutdown.is_none(), "{:?}", proof.failures);
    assert_eq!(proof.certificates, 0);
    assert!(!proof.timed_out, "retained receive deadline elapsed");
    assert_eq!(proof.read.failed, fail);
    if fail {
        let read = proof
            .read
            .observed
            .expect("failed and resumed read observations");
        assert!(!read.before);
        assert_eq!(
            read.failed.result,
            Err(Capacity::Allocation {
                error: alloc::Error::Exhausted,
                requested: read.expected,
            })
        );
        assert_eq!(read.failed.activity.allocations, 0);
        assert_eq!(read.failed.activity.deallocations, 0);
        assert!(read.failed.fin);
        assert!(!read.failed.eof);
        assert_eq!(read.resumed.length, read.expected);
        assert_eq!(read.resumed.activity.allocations, 1);
        assert_eq!(read.resumed.activity.allocated_bytes, read.expected);
        assert!(read.resumed.eof);
        assert_eq!(read.drained, Ok(None));
    } else if proof.read.stream {
        assert_eq!(
            proof
                .read
                .barrier
                .as_ref()
                .and_then(|value| value.as_deref()),
            Some(&b"retained stream lifetime barrier"[..])
        );
    }
    proof
        .received
        .expect("the retained server must capture the first payload")
}

#[test]
fn owns_small_exactly() {
    let payload = b"compact";
    let (bytes, resident) = verify(
        mode(payload.to_vec(), false, false, recover, complete).expect("retained fixture"),
        false,
    );
    assert_eq!(bytes, payload);
    assert_eq!(resident, payload.len());
}

#[test]
fn retains_large_owner() {
    let payload = [0xa5; 1000];
    let (bytes, resident) = verify(
        mode(payload.to_vec(), false, false, recover, complete).expect("retained fixture"),
        false,
    );
    assert_eq!(bytes, payload);
    assert!(resident >= ENDPOINT.packet_buffer_bytes as usize);
}

#[test]
fn retains_stream_owner() {
    let payload = [0xd8; 1000];
    let (bytes, resident) = verify(
        mode(payload.to_vec(), true, false, recover, complete).expect("retained fixture"),
        false,
    );
    assert_eq!(bytes, payload);
    assert!(resident >= ENDPOINT.packet_buffer_bytes as usize);
}

#[test]
fn reuses_pooled_tls() {
    let payload = [0x7c; 1000];
    let (proof, reports, opening) =
        pooled(payload.to_vec(), recover, complete).expect("pooled fixture");
    assert_eq!(opening, [true, true]);
    let (bytes, resident) = verify((proof, reports), false);
    assert_eq!(bytes, payload);
    assert!(resident >= ENDPOINT.packet_buffer_bytes as usize);
}

#[test]
fn compact_read_recovers() {
    let payload = b"retained";
    let (bytes, resident) = verify(
        mode(payload.to_vec(), true, true, recover, complete).expect("retained fixture"),
        true,
    );
    assert_eq!(bytes, payload);
    assert_eq!(resident, payload.len());
}

#[test]
fn plural_read_recovers() {
    let payload: [u8; 2048] = array::from_fn(|index| index as u8);
    let (bytes, resident) = verify(
        mode(payload.to_vec(), true, true, recover, complete).expect("retained fixture"),
        true,
    );
    assert_eq!(bytes, payload);
    assert_eq!(resident, payload.len());
}
