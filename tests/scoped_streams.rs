pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use peer::Pair;

#[test]
fn retains_stream_identity() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("fixture peers must establish");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let local = (client.streams().send().open_bidi())
                .expect("established peer must grant a bidirectional stream");
            let peer = (server.streams().view().resolve_bidi(local.id()))
                .expect("the peer must accept the transmitted stream direction");
            let mut now = Instant::now() + Duration::from_millis(20);
            for payload in [b"first".as_slice(), b"second".as_slice()] {
                assert!(client.streams().send().send(local.send(), payload).is_ok());
                let (flight, result) = client.output().send(now);
                result.expect("configured journals must admit stream output");
                for mut packet in flight {
                    assert!(
                        server
                            .input(&mut work)
                            .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                            .is_ok()
                    );
                }
                let mut received = Vec::new();
                assert!(matches!(
                    server.streams().receive().recv(peer.receive(), &mut received),
                    Ok(length) if length == payload.len()
                ));
                assert_eq!(received, payload);
                assert!(server.streams().send().send(peer.send(), &received).is_ok());
                now += Duration::from_millis(20);
                let (flight, result) = server.output().send(now);
                result.expect("configured journals must admit response output");
                for mut packet in flight {
                    assert!(
                        client
                            .input(&mut work)
                            .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                            .is_ok()
                    );
                }
                let mut response = Vec::new();
                assert!(matches!(
                    client.streams().receive().recv(local.receive(), &mut response),
                    Ok(length) if length == payload.len()
                ));
                assert_eq!(response, payload);
                now += Duration::from_millis(20);
            }
            assert!(client.streams().send().finish(local.send()).is_ok());
            assert!(server.streams().send().finish(peer.send()).is_ok());
        });
    });
}
