use crate::common::peer;
pub mod common;
use std::array;

use dope_quic::conn::wire::path::probe;
use dope_test::alloc::Tracker;
use o3::{alloc, depot::capacity};
use peer::{Receiver as _, warm::Exchange};

#[test]
fn pressure() {
    let mut exchange = Exchange::try_new().expect("connected peers");
    let tokens: [[u8; 8]; 64] = array::from_fn(|index| (index as u64).to_ne_bytes());
    exchange.try_probe(&tokens).expect("challenge flight");
    let sample = Tracker::begin();
    exchange.try_respond().expect("server response flight");
    let cold = sample.finish();
    assert!(
        cold.allocations > 0,
        "the first output batch owns its new backing"
    );
    assert!(!exchange.responses.is_empty());
    exchange
        .try_finish()
        .expect("all responses and acknowledgements must settle");
    assert!(
        tokens
            .iter()
            .all(|token| exchange.pair.client.view().path().has_token(token))
    );

    for _ in 0..2 {
        let sample = Tracker::begin();
        exchange.try_probe(&tokens).expect("challenge flight");
        exchange.try_respond().expect("server response flight");
        assert!(!exchange.responses.is_empty());
        exchange
            .try_finish()
            .expect("all responses and acknowledgements must settle");
        let hot = sample.finish();
        assert_eq!(
            hot.allocations, 0,
            "repeated exchange: {} bytes",
            hot.allocated_bytes
        );
        assert_eq!(hot.allocated_bytes, 0);
    }
}

#[test]
fn admission() {
    let mut exchange = Exchange::try_new().expect("connected peers");
    let tokens = [
        1_u64.to_ne_bytes(),
        2_u64.to_ne_bytes(),
        3_u64.to_ne_bytes(),
    ];
    let ((), inline) = Tracker::measure(|| {
        for &token in &tokens[..2] {
            exchange
                .pair
                .client
                .with_scope(|mut scope| scope.path().try_probe(token))
                .expect("inline challenge");
        }
    });
    assert_eq!(inline, [0; 4]);
    let error = Tracker::fail_after(0, || {
        exchange
            .pair
            .client
            .with_scope(|mut scope| scope.path().try_probe(tokens[2]))
    });
    assert_eq!(
        error,
        Err(probe::Error::Capacity {
            data: tokens[2],
            reason: capacity::Reason::Allocation(alloc::Error::Exhausted),
        })
    );
    for &token in &tokens[..2] {
        assert_eq!(
            exchange
                .pair
                .client
                .with_scope(|mut scope| scope.path().try_probe(token)),
            Err(probe::Error::Duplicate { data: token })
        );
    }
    let ((), spill) = Tracker::measure(|| {
        exchange
            .pair
            .client
            .with_scope(|mut scope| scope.path().try_probe(tokens[2]))
            .expect("retry allocation");
    });
    assert_eq!(spill, [1, 64 * 40, 0, 0]);
    exchange.try_send().expect("client flight");
    exchange.try_respond().expect("server response flight");
    exchange
        .try_finish()
        .expect("all responses and acknowledgements must settle");
    assert!(
        tokens
            .iter()
            .all(|token| exchange.pair.client.view().path().has_token(token))
    );
}

#[test]
fn eviction() {
    let mut exchange = Exchange::try_new().expect("connected peers");
    let tokens: [[u8; 8]; 64] = array::from_fn(|index| (index as u64).to_ne_bytes());
    exchange.try_probe(&tokens).expect("challenge flight");
    exchange.try_respond().expect("server response flight");
    exchange
        .try_finish()
        .expect("all responses and acknowledgements must settle");
    assert!(
        tokens
            .iter()
            .all(|token| exchange.pair.client.view().path().has_token(token))
    );

    let token = 64_u64.to_ne_bytes();
    let ((), counts) = Tracker::measure(|| {
        exchange.try_probe(&[token]).expect("challenge flight");
        exchange.try_respond().expect("server response flight");
        exchange
            .try_finish()
            .expect("all responses and acknowledgements must settle");
    });
    assert_eq!(counts, [0; 4]);
    assert!(exchange.pair.client.view().path().has_token(&token));
    assert_eq!(
        tokens
            .iter()
            .filter(|token| exchange.pair.client.view().path().has_token(token))
            .count(),
        63
    );
}

#[test]
fn cache_failure() {
    let mut exchange = Exchange::try_new().expect("connected peers");
    let tokens = [1_u64.to_ne_bytes(), 2_u64.to_ne_bytes()];
    exchange.try_probe(&tokens).expect("challenge flight");
    exchange.try_respond().expect("server response flight");
    exchange
        .try_finish()
        .expect("all responses and acknowledgements must settle");
    let token = 3_u64.to_ne_bytes();
    exchange.try_probe(&[token]).expect("challenge flight");
    exchange.try_respond().expect("server response flight");
    assert_eq!(exchange.responses.packets(), 1);
    let packet = exchange
        .responses
        .iter_mut()
        .next()
        .expect("response packet");
    let mut retry = packet.to_vec();
    Tracker::fail_after(0, || {
        assert!(
            exchange
                .pair
                .client
                .receive(&mut exchange.pair.work, packet, exchange.at)
                .is_ok(),
            "cache pressure drops the packet without closing the connection"
        );
    });
    assert!(!exchange.pair.client.view().path().has_token(&token));
    assert!(
        tokens
            .iter()
            .all(|token| exchange.pair.client.view().path().has_token(token))
    );
    let ((), counts) = Tracker::measure(|| {
        assert!(
            exchange
                .pair
                .client
                .receive(&mut exchange.pair.work, &mut retry, exchange.at)
                .is_ok(),
            "the outstanding challenge survives rejected cache admission"
        );
    });
    assert_eq!(counts, [1, 64 * 8, 0, 0]);
    assert!(exchange.pair.client.view().path().has_token(&token));
    assert!(exchange.pair.client.view().lifecycle().is_ready());
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
