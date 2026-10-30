pub mod common;
use crate::common::peer;
use common::suite::peers::config;
use std::time::{Duration, Instant};

use dope_quic::conn::stream;
use dope_quic::wire::stream::Id;
use peer::Pair;
use peer::Receiver as _;

#[test]
fn later_stream_progresses() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(
        config::try_bounds().expect("server stream limits"),
        config::try_bounds().expect("client stream limits"),
    )
    .expect("establish peers with stream limits");
    let now = Instant::now() + Duration::from_millis(20);
    assert!(
        client
            .with_scope(|mut scope| {
                let mut streams = scope.streams();
                let mut send = streams.send();
                for index in 0..300u64 {
                    let stream = send.open_bidi()?;
                    assert_eq!(stream.get(), index * 4);
                    if index < 256 {
                        send.send(stream.send(), &[0x31; 1 << 15])?;
                    } else {
                        send.send(stream.send(), &[index as u8])?;
                    }
                }
                Ok::<_, stream::Error>(())
            })
            .is_ok(),
        "configured streams must admit their payloads"
    );

    assert!(server.receive_from(&mut work, &mut client, now).is_ok());
    let ack_at = now + Duration::from_millis(20);
    assert!(client.receive_from(&mut work, &mut server, ack_at).is_ok());
    let next = ack_at + Duration::from_millis(20);
    assert!(server.receive_from(&mut work, &mut client, next).is_ok());

    let target = (Id::new(256 * 4)).expect("target wire ID must fit");
    let mut received = Vec::new();
    let result = server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let target = streams.view().resolve_recv(target)?;
        Ok::<_, stream::Error>(streams.receive().recv(target, &mut received))
    });
    assert!(matches!(result, Ok(Ok(1))));
    assert_eq!(received, vec![0]);
}
