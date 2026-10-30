pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn::stream::Error;
use dope_quic::errors::Code;
use peer::Bind as _;
use peer::Config;
use peer::Event;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

#[test]
fn retains_local_reset() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("connected peers");
    let opening = client.send_streams().open_bidi().expect("reset stream");
    let reset_rx = opening.receive();
    let reset = opening.bind(&server).expect("reset send half");
    let now = Instant::now();
    client
        .send_streams()
        .finish(opening)
        .expect("announce stream");
    server
        .receive_from(&mut work, &mut client, now)
        .expect("stream announcement");
    let live = server.send_streams().open_uni().expect("live stream");
    let live_rx = live.bind(&client).expect("live receive half");
    server
        .send_streams()
        .send(reset, b"discarded")
        .expect("reset bytes");
    server
        .send_streams()
        .send(live, b"survives")
        .expect("live bytes");
    server.send_streams().finish(live).expect("live final size");
    server
        .send_streams()
        .reset(reset, Code::ZERO)
        .expect("local reset");
    client.recv().stop(reset_rx, Code::MAX).expect("peer stop");
    server
        .receive_from(&mut work, &mut client, now)
        .expect("STOP delivery");
    assert_eq!(
        server.stream_state().stopped(reset).expect("observed STOP"),
        Some(Code::MAX)
    );
    client
        .receive_from(&mut work, &mut server, now)
        .expect("RESET and live data");
    let mut resets = 0;
    while let Some(event) = client.poll().poll_event() {
        if let Event::Reset {
            stream_id: id,
            error_code: code,
        } = event
        {
            assert!(id == reset_rx);
            assert_eq!(code, Code::ZERO);
            resets += 1;
        }
    }
    assert_eq!(resets, 1);
    assert_eq!(
        client
            .recv()
            .recv_owned(live_rx)
            .expect("live receive")
            .as_deref(),
        Some(&b"survives"[..])
    );
}

#[test]
fn keeps_stream_credit() {
    let options = || {
        Config::new(5, 5, 8, 1)
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds")
    };
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(options(), options()).expect("connection pair must initialize");
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open the configured unidirectional stream");
    let peer = stream.bind(&client);
    let peer = (peer).expect("paired stream must resolve");
    let now = Instant::now();

    server
        .send_streams()
        .send(stream, b"owned")
        .expect("server can send the owned batch");
    let received = client.receive_from(&mut work, &mut server, now);
    assert!(received.is_ok());
    let (_, credit) = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("owned batch is available to hold")
        .into_parts();
    let credit = client
        .release_conn(credit)
        .expect("held batch can release only its connection credit");

    server
        .send_streams()
        .reset(stream, Code::from_u8(0x93))
        .expect("server can reset the open stream");
    let received = client.receive_from(&mut work, &mut server, now);
    assert!(received.is_ok());
    assert!(
        client.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer,
                error_code: dope_quic::errors::Code::from_u8(0x93),
            })
    );
    let received = server.receive_from(&mut work, &mut client, now);
    assert!(received.is_ok());
    assert!(matches!(
        server.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    assert!(
        client.release(credit).is_ok(),
        "tombstone preserves the held stream credit"
    );
    let received = server.receive_from(&mut work, &mut client, now);
    assert!(received.is_ok());
    assert!(server.send_streams().open_uni().is_ok());
}

#[test]
fn holds_credit() {
    let options = || {
        Config::new(5, 5, 8, 1)
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds")
    };
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(options(), options()).expect("connection pair must initialize");
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open the configured unidirectional stream");
    let peer = stream.bind(&client);
    let peer = (peer).expect("paired stream must resolve");
    server
        .send_streams()
        .send(stream, b"owned")
        .expect("server can send the owned batch");
    let data_at = Instant::now() + Duration::from_secs(1);
    let received = client.receive_from(&mut work, &mut server, data_at);
    assert!(received.is_ok());
    let held = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("owned batch is available to hold");

    server
        .send_streams()
        .reset(stream, Code::from_u8(0x91))
        .expect("server can reset the open stream");
    let reset_at = data_at + Duration::from_millis(1);
    let received = client.receive_from(&mut work, &mut server, reset_at);
    assert!(received.is_ok());
    assert!(
        client.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer,
                error_code: dope_quic::errors::Code::from_u8(0x91),
            })
    );
    let received = server.receive_from(&mut work, &mut client, reset_at);
    assert!(received.is_ok());
    assert!(matches!(
        server.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    assert_eq!(
        client
            .release_held(held)
            .map_err(|cause| cause.kind())
            .expect("reset tombstone preserves the held batch credit")
            .as_slice(),
        b"owned"
    );
    let received = server.receive_from(&mut work, &mut client, reset_at);
    assert!(received.is_ok());
    let next = server
        .send_streams()
        .open_uni()
        .expect("released credit admits a replacement stream");
    let next_rx = next.bind(&client);
    let next_rx = (next_rx).expect("replacement stream must resolve");
    server
        .send_streams()
        .send(next, b"again")
        .expect("server can send on the replacement stream");
    server
        .send_streams()
        .finish(next)
        .expect("server can finish the replacement stream");
    let received = client.receive_from(&mut work, &mut server, reset_at);
    assert!(received.is_ok());
    assert_eq!(
        client
            .recv()
            .recv_owned(next_rx)
            .expect("client can move the replacement stream batch")
            .as_deref(),
        Some(&b"again"[..])
    );
}

#[test]
fn discards_unread() {
    let options = || {
        let mut config = Config::new(5, 5, 0, 1);
        config.local = Some([0, 1]);
        config
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds")
    };
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(options(), options()).expect("connection pair must initialize");
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open the configured unidirectional stream");
    server
        .send_streams()
        .send(stream, b"waste")
        .expect("server can send the unread batch");
    let data_at = Instant::now() + Duration::from_secs(1);
    let received = client.receive_from(&mut work, &mut server, data_at);
    assert!(received.is_ok());

    server
        .send_streams()
        .reset(stream, Code::from_u8(0x92))
        .expect("server can reset the open stream");
    let reset_at = data_at + Duration::from_millis(1);
    let received = client.receive_from(&mut work, &mut server, reset_at);
    assert!(received.is_ok());
    let ack_at = client
        .view()
        .recovery()
        .send_at(reset_at + Duration::from_millis(30));
    let received = server.receive_from(&mut work, &mut client, ack_at);
    assert!(received.is_ok());

    let next = server
        .send_streams()
        .open_uni()
        .expect("discarded unread credit admits a replacement stream");
    let next_rx = next.bind(&client);
    let next_rx = (next_rx).expect("replacement stream must resolve");
    server
        .send_streams()
        .send(next, b"fresh")
        .expect("server can send on the replacement stream");
    server
        .send_streams()
        .finish(next)
        .expect("server can finish the replacement stream");
    let received = client.receive_from(&mut work, &mut server, ack_at);
    assert!(received.is_ok());
    assert_eq!(
        client
            .recv()
            .recv_owned(next_rx)
            .expect("client can move the replacement stream batch")
            .as_deref(),
        Some(&b"fresh"[..])
    );
    assert_eq!(client.stream_state().recv_eof(next_rx), Ok(true));
}
