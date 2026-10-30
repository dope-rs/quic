use common::peer::Pair;
use common::peer::Receiver;
use common::peer::Scope as _;
pub mod common;
use common::peer;

use std::mem;
use std::time::{Duration, Instant};

use dope_quic::errors::Code;
use dope_quic::wire::frame::{self, Frame, View, close};
use dope_quic::wire::varint::VarInt;
use peer::Event;

#[test]
fn proves_layout() {
    assert_eq!(mem::size_of::<Code>(), mem::size_of::<u64>());
    assert_eq!(mem::align_of::<Code>(), mem::align_of::<u64>());
    assert!(Code::new(u64::MAX).is_none());
    assert_eq!(Code::MAX.get(), VarInt::MAX);
}

#[test]
fn decodes_reset() {
    let code = Code::MAX;
    let mut wire = vec![frame::TYPE_RESET_STREAM];
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");
    VarInt::MAX_VALUE.encode(&mut wire).expect("wire encoding");
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");

    let (decoded, consumed) =
        Frame::decode_ref(&wire).expect("constructed RESET_STREAM frame decodes");
    assert_eq!(consumed, wire.len());
    assert!(matches!(
        decoded.view(),
        View::ResetStream { error_code, .. } if error_code == code
    ));
}

#[test]
fn decodes_close() {
    let code = Code::MAX;
    let mut wire = vec![frame::TYPE_CONNECTION_CLOSE_APP];
    VarInt::MAX_VALUE.encode(&mut wire).expect("wire encoding");
    VarInt::ZERO.encode(&mut wire).expect("wire encoding");

    let (decoded, consumed) =
        Frame::decode_ref(&wire).expect("constructed application close frame decodes");
    assert_eq!(consumed, wire.len());
    assert!(matches!(
        decoded.view(),
        View::ConnectionClose {
            code: close::Code::Application(decoded),
            ..
        } if decoded == code
    ));
}

#[test]
fn roundtrips_max() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let code = Code::MAX;
    let stream = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let mut send = streams.send();
        let stream = send
            .open_uni()
            .expect("default peer limit permits one unidirectional stream");
        let id = stream.id();
        send.reset(stream, code)
            .expect("fresh stream accepts one reset");
        id
    });

    Receiver::receive_from(
        &mut server,
        &mut work,
        &mut client,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("peer packet transfer");

    assert!(
        server.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer::ReceiveId::from(stream),
                error_code: Code::MAX,
            })
    );
}
