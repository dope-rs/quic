pub mod common;

use common::{
    peer::{Bind as _, Config, Pair, Receiver as _, Scope as _},
    suite::commit::Retain,
};
use dope_quic::{
    conn::stream::{Error, SendOutcome},
    errors::Code,
    stream::send::{self, admit},
    wire::stream::Id,
};
use std::time::{Duration, Instant};

#[test]
fn implicit_send_capacity() {
    let mut config = Config::new(1 << 20, 1 << 20, 2, 0);
    config.local = Some([0, 0]);
    let mut pair = Pair::try_new(
        config.try_build().expect("two resident slots"),
        Config::default().try_build().expect("client options"),
    )
    .expect("connected peers");
    let mut now = Instant::now() + Duration::from_secs(1);
    for index in 0..2 {
        let id = pair.client.send_streams().open_bidi().expect("peer credit");
        pair.client.send_streams().finish(id).expect("peer FIN");
        pair.server
            .receive_from(&mut pair.work, &mut pair.client, now)
            .expect("peer FIN delivery");
        let peer = id.bind(&pair.server).expect("received stream");
        if index == 0 {
            pair.server.with_scope(|mut scope| {
                let mut streams = scope.streams();
                let handle = streams.resident().handle(id.id()).expect("resident stream");
                streams
                    .binding()
                    .try_attach(handle)
                    .expect("retain binding");
            });
        }
        pair.server
            .recv()
            .recv_owned(peer)
            .expect("consume peer FIN");
        pair.server
            .send_streams()
            .finish(peer)
            .expect("response FIN");
        now += Duration::from_millis(30);
        pair.client
            .receive_from(&mut pair.work, &mut pair.server, now)
            .expect("response FIN delivery");
        pair.client
            .recv()
            .recv_owned(id)
            .expect("consume response FIN");
        now += Duration::from_millis(30);
        pair.exchange(now, 2)
            .expect("FIN acknowledgement and stream credit");
        while pair.server.poll().poll_event().is_some() {}
        while pair.client.poll().poll_event().is_some() {}
    }

    let low = pair
        .client
        .send_streams()
        .open_bidi()
        .expect("released peer credit");
    let high = pair
        .client
        .send_streams()
        .open_bidi()
        .expect("released peer credit");
    assert_eq!((low.get(), high.get()), (8, 12));
    pair.client
        .send_streams()
        .send(high, &[1])
        .expect("higher stream");
    now += Duration::from_millis(30);
    pair.server
        .receive_from(&mut pair.work, &mut pair.client, now)
        .expect("implicit lower stream opening");
    let low = low.bind(&pair.server).expect("implicitly opened stream");
    assert_eq!(
        pair.server.send_streams().send(low, &[2]),
        Err(Error::Capacity)
    );
    assert_eq!(pair.server.send_streams().finish(low), Err(Error::Capacity));
    assert_eq!(
        pair.server.send_streams().reset(low, Code::ZERO),
        Err(Error::Capacity)
    );

    let owner = vec![3; 64];
    let pointer = owner.as_ptr();
    let owner = match pair
        .server
        .send_streams()
        .try_buffer(low, send::Buffer::Owned(owner))
    {
        SendOutcome::Failed { owner, error } => {
            assert_eq!(error, Error::Capacity);
            Some(owner)
        }
        _ => None,
    }
    .expect("resident capacity must reject the unchanged owner");
    assert_eq!(owner.as_slice().as_ptr(), pointer);
    let owner = pair.server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let id = streams.view().resolve_send(low.id()).expect("send access");
        let (owner, Retain) = match streams.send().try_admit(id, owner, Retain) {
            admit::Outcome::Failed {
                owner,
                commit,
                error,
            } => {
                assert_eq!(error, Error::Capacity);
                Some((owner, commit))
            }
            _ => None,
        }
        .expect("observed admission must preserve owner and commit");
        owner
    });
    assert_eq!(owner.as_slice().as_ptr(), pointer);
    assert_eq!(pair.server.stream_state().wire_bytes(), 0);
    assert_eq!(pair.server.stream_state().resident(), 0);

    pair.server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .resident()
            .handle(Id::ZERO)
            .expect("retained old binding");
        streams
            .binding()
            .try_release(handle)
            .expect("release old binding");
    });
    assert!(matches!(
        pair.server.send_streams().try_buffer(low, owner),
        SendOutcome::Accepted
    ));
    now += Duration::from_millis(30);
    pair.client
        .receive_from(&mut pair.work, &mut pair.server, now)
        .expect("retry delivery");
    let low = low.bind(&pair.client).expect("original stream");
    assert_eq!(
        pair.client.recv().recv_owned(low).expect("retry bytes"),
        Some(vec![3; 64])
    );
}
