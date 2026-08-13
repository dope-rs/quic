pub mod support;

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use dope_quic::packet::ConnectionId;
use dope_quic::transport_params::{self, Params, TransportParameterError};
use dope_quic::varint::VarInt;

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

fn push_parameter(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    VarInt::new(id).expect("test ID fits").encode(out);
    VarInt::from_usize(value.len())
        .expect("test value length fits")
        .encode(out);
    out.extend_from_slice(value);
}

fn is_reserved(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

#[test]
fn decode_materializes_semantics_without_allocating() {
    let expected = Params {
        initial_source_connection_id: Some(
            ConnectionId::try_from(&[0x11; 20][..]).expect("maximum-length CID"),
        ),
        original_destination_connection_id: Some(
            ConnectionId::try_from(&[0x22; 20][..]).expect("maximum-length CID"),
        ),
        retry_source_connection_id: Some(
            ConnectionId::try_from(&[0x33; 20][..]).expect("maximum-length CID"),
        ),
        max_datagram_frame_size: Some(65_527),
        stateless_reset_token: Some([0x44; 16]),
        ..Params::default()
    };
    let mut wire = Vec::with_capacity(Params::MAX_ENCODED_LEN);
    expected.encode(&mut wire).expect("valid parameters");

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.set(true);
    let decoded = Params::decode(&wire);
    COUNTING.set(false);

    assert_eq!(decoded, Ok(expected));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
}

#[test]
fn decode_enforces_the_exact_non_reserved_parameter_budget() {
    let mut wire = Vec::new();
    let mut id = 1_000;
    for _ in 0..transport_params::MAX_PARAMETERS {
        while is_reserved(id) {
            id += 1;
        }
        push_parameter(&mut wire, id, &[]);
        id += 1;
    }
    assert!(Params::decode(&wire).is_ok());

    while is_reserved(id) {
        id += 1;
    }
    push_parameter(&mut wire, id, &[]);
    assert_eq!(Params::decode(&wire), Err(TransportParameterError::TooMany));
}

#[test]
fn reserved_parameters_do_not_consume_the_forward_compatibility_budget() {
    let mut wire = Vec::new();
    for n in 0..=transport_params::MAX_PARAMETERS {
        push_parameter(&mut wire, 31 * n as u64 + 27, &[]);
    }
    assert!(Params::decode(&wire).is_ok());
}

#[test]
fn duplicate_unknown_parameter_is_rejected_without_hashing() {
    let mut wire = Vec::new();
    push_parameter(&mut wire, 1_000, &[]);
    push_parameter(&mut wire, 1_000, &[]);
    assert_eq!(
        Params::decode(&wire),
        Err(TransportParameterError::Duplicate)
    );
}
