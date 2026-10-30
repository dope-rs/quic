pub mod common;

use common::{
    peer::Scope as _,
    suite::{commit::Retain, peers::config::try_budget},
};
use dope_quic::{
    conn::stream::SendOutcome,
    errors::Code,
    stream::{
        release,
        send::{self, admit},
    },
};
use o3::buffer::storage;

#[test]
fn empty_owners() {
    let mut pair = try_budget(64, 64, 2).expect("send budgets");
    let client = &mut pair.client;
    let stream = client.send_streams().open_bidi().expect("local stream");
    assert!(matches!(
        client
            .send_streams()
            .try_buffer(stream, send::Buffer::Owned(Vec::with_capacity(64))),
        SendOutcome::Accepted
    ));
    assert_eq!(client.stream_state().resident(), 0);

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .view()
            .resolve_send(stream.id())
            .expect("send access");
        let parts = send::Parts::new(
            send::Buffer::Retained(storage::Shared::new()),
            Some(send::Buffer::Retained(storage::Shared::new())),
            send::Boundary::More,
        );
        assert!(matches!(
            streams.send().try_admit(stream, parts, Retain),
            admit::Outcome::Retained((_, send::Boundary::More, owners)) if owners.is_empty()
        ));
        let mut released = None;
        streams
            .send()
            .reset_with(stream, Code::ZERO, &mut |event| released = Some(event))
            .expect("empty stream reset");
        let released = released.expect("reset emits terminal evidence");
        assert!(released.source.id() == stream.id());
        assert!(matches!(released.cause, release::Cause::Reset));
        assert!(released.charge.is_empty());
    });
    let next = client.send_streams().open_bidi().expect("next stream");
    assert!(matches!(
        client
            .send_streams()
            .try_buffer(next, send::Buffer::Owned(vec![1; 64])),
        SendOutcome::Accepted
    ));
    assert_eq!(client.stream_state().active_bytes(), 64);
}
