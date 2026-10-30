use dope_quic::{config::raw::Identity, conn::life::tls::clients::Authority, errors::Connect};
use dope_test::alloc::Tracker;
use rustls::pki_types::ServerName;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn policy_alloc_fails() {
    drop(Identity::client([17; 32]).expect("initialize native config"));

    let (result, activity) = Tracker::activity(|| {
        let config = Identity::client([17; 32]).expect("complete client config");
        let name = ServerName::try_from("example.com").expect("borrowed server name");
        Tracker::fail_after(1, || Authority::try_new(config, name))
            .map(drop)
            .map_err(Connect::from)
    });
    assert!(matches!(
        result,
        Err(Connect::Allocation(o3::alloc::Error::Exhausted))
    ));
    assert_eq!(activity.allocations, activity.deallocations);
    assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);

    let config = Identity::client([17; 32]).expect("retry client config");
    let name = ServerName::try_from("example.com").expect("borrowed server name");
    drop(Authority::try_new(config, name).expect("retry authority owner"));
}
