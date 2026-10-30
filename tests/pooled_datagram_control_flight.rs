pub mod common;

use common::peer::Scope as _;
use common::peer::{Bind as _, Config, Pair, Receiver as _};
use common::suite::owners;
use dope_quic::conn::wire::packet::Batch;
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::Arena;
use std::time::{Duration, Instant};

/// Unacknowledged MAX_DATA/MAX_STREAM_DATA owners retain control-flight priority.
#[test]
fn admits_after_control() {
    let [server, client] = [(); 2].map(|()| {
        Config::new(1, 1, 1, 1)
            .try_build()
            .expect("one-byte flow windows")
            .into_builder()
            .transport(|path| path.max_pmtu(1200))
            .try_build()
            .expect("fixed path MTU")
    });
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(server, client).expect("established pair");
    let now = Instant::now() + Duration::from_secs(1);
    let stream = server.send_streams().open_uni().expect("server stream");
    let received = stream.bind(&client).expect("client receive stream");
    server
        .send_streams()
        .send(stream, b"x")
        .expect("one byte of flow credit");
    client
        .receive_from(&mut work, &mut server, now)
        .expect("deliver stream byte");
    assert_eq!(
        client.recv().recv_owned(received).expect("consume stream"),
        Some(b"x".to_vec())
    );
    let arena = Arena::try_new(1, 1200).expect("packet arena");
    let mut packet = arena.try_acquire(1).expect("packet slot");
    packet.payload_mut()[0] = 7;
    let packet = match client
        .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200))
        .err()
        .expect("queued receive credit must retain priority")
    {
        SendFailure::Full(packet) => Some(packet),
        _ => None,
    }
    .expect("queued receive credit must return the full packet");

    let mut control = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut control, now, 1, 1200))
        .expect("emit receive credit");
    assert_eq!(control.packets(), 1);

    let at = client
        .view()
        .recovery()
        .send_at(now + Duration::from_millis(1));
    let result = client.with_scope(|mut scope| scope.output().try_packet(packet, at, 1200));
    let sealed = result
        .as_ref()
        .map_err(owners::rejection)
        .expect("pooled datagram must seal after control admission");
    let mut wire = sealed.as_ref().to_vec();
    server
        .with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut wire, at, |_: &rustls::Error| {})
        })
        .expect("receive pooled datagram");
    assert_eq!(
        server.with_scope(|mut scope| scope.datagrams().recv()),
        Some(vec![7])
    );
    drop(result);

    let deadline = client
        .view()
        .recovery()
        .next_timer()
        .expect("unacknowledged flight arms recovery");
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(deadline)),
        Ok(())
    );
    let packet = arena.try_acquire(1).expect("recycled packet slot");
    assert!(matches!(
        client.with_scope(|mut scope| scope.output().try_packet(packet, deadline, 1200)),
        Err(SendFailure::Full(_))
    ));
}
