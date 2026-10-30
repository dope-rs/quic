use dope_quic::{
    config::raw::Identity,
    conn::{
        life::{
            accept::{Authority, Ids},
            options::Options,
        },
        stream::Build,
    },
    errors::Connect,
    wire::packet::cid,
};
use dope_test::alloc::Tracker;
use o3::{alloc::Error::Exhausted, buffer::storage::Shared};

/// Counts from the end past two connection scratch buffers to target five
/// stream allocation failures independently of TLS allocation counts.
#[test]
fn allocation_returns() {
    let config = Identity::from_seed(&[0x39; 32])
        .expect("identity")
        .server()
        .expect("server config");
    let auth = Authority::<0>::new(config, Options::default()).expect("authority");
    let cid = cid::Id::try_from([0x71; 8]).expect("connection ID");
    let accept = || auth.accept::<Shared>(Ids::initial(cid, cid, cid));
    let (result, count) = Tracker::count(accept);
    drop(result.expect("allocation baseline"));

    for (suffix, expected) in [
        (10, Build::Send(Exhausted)),
        (9, Build::Receive(Exhausted)),
        (5, Build::Resident(Exhausted)),
        (4, Build::Resident(Exhausted)),
        (3, Build::Schedule(Exhausted)),
    ] {
        let budget = count.checked_sub(suffix).expect("stream storage");
        let (result, activity) = Tracker::activity(|| Tracker::fail_after(budget, accept));
        assert!(matches!(result, Err(Connect::Stream(error)) if error == expected));
        assert_eq!(activity.allocations, activity.deallocations);
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
