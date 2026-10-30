use dope_quic::conn::Workspace;
use dope_test::alloc::Tracker;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn workspace_recovery() {
    let (work, acquired) = Tracker::activity(Workspace::try_new);
    let work = work.expect("receive workspace allocation");
    let ((), released) = Tracker::activity(|| drop(work));
    assert_eq!(released.deallocations, acquired.allocations);
    assert_eq!(released.deallocated_bytes, acquired.allocated_bytes);

    for limit in 0..acquired.allocations {
        let (result, activity) =
            Tracker::activity(|| Tracker::fail_after(limit, Workspace::try_new));
        assert!(matches!(result, Err(o3::alloc::Error::Exhausted)));
        assert_eq!(activity.allocations, limit);
        assert_eq!(activity.deallocations, limit);
        assert_eq!(activity.deallocated_bytes, activity.allocated_bytes);
    }
    assert!(Workspace::try_new().is_ok());
}
