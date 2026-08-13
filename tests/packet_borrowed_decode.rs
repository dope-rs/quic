pub mod support;

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use dope_quic::packet::{
    ConnectionId, ConnectionIdError, ConnectionIdRef, InitialHeader, QUIC_V1, Retry, RetryRef,
};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn record_allocation(_size: usize) {
    if COUNTING.get() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: support::Allocator = support::Allocator::new(record_allocation);

#[test]
fn long_header_decode_borrows_without_allocating() {
    let (wire, _) = InitialHeader {
        version: QUIC_V1,
        dcid: vec![0x11; 8],
        scid: vec![0x22; 8],
        token: vec![0x33; 32],
        packet_number: 0,
        pn_len: 1,
    }
    .encode_with_pn(0)
    .unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    let prefix = InitialHeader::decode_pre_hp(&wire).unwrap();
    let owned = prefix.dcid.into_owned();
    COUNTING.set(false);

    assert_eq!(prefix.dcid, [0x11; 8]);
    assert_eq!(prefix.scid, [0x22; 8]);
    assert_eq!(prefix.token, [0x33; 32]);
    assert_eq!(prefix.dcid.as_ptr(), wire[6..].as_ptr());

    assert_eq!(owned.as_slice(), &[0x11; 8]);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
}

#[test]
fn owned_connection_id_enforces_the_wire_bound_in_21_bytes() {
    assert_eq!(std::mem::size_of::<ConnectionId>(), 21);
    assert!(ConnectionId::try_from(&[0; 20][..]).is_ok());
    assert_eq!(
        ConnectionId::try_from(&[0; 21][..]),
        Err(ConnectionIdError::TooLong)
    );
}

#[test]
fn retry_verification_borrows_wire_and_reuses_the_one_required_token_allocation() {
    let original_dcid = [0x11; 8];
    let expected_dcid = [0x22; 8];
    let peer_cid = [0x33; 8];
    let token = [0x44; 48];
    let mut packet = Retry {
        version: QUIC_V1,
        dcid: expected_dcid.to_vec(),
        scid: peer_cid.to_vec(),
        token: token.to_vec(),
        integrity_tag: [0; 16],
    };
    packet.integrity_tag = packet.compute_integrity_tag(&original_dcid).unwrap();
    let wire = packet.encode().unwrap();
    let mut storage = Vec::new();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    let verified = RetryRef::decode(&wire)
        .unwrap()
        .verify_into(
            ConnectionIdRef::new(&original_dcid).unwrap(),
            ConnectionIdRef::new(&expected_dcid).unwrap(),
            &mut storage,
        )
        .unwrap()
        .unwrap();
    let owned_peer_cid = verified.source_connection_id().into_owned();
    let token_len = verified.token().len();
    COUNTING.set(false);

    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 1);
    assert_eq!(owned_peer_cid.as_slice(), peer_cid);
    assert_eq!(token_len, token.len());
    assert_eq!(storage, token);
}
