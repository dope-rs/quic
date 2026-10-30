pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::errors::Code;
use peer::Bind as _;
use peer::Config;
use peer::Event;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

#[test]
fn traverses_after_removal() {
    let config = || {
        (Config::new(32, 1 << 20, 0, 128)
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds")
            .into_builder()
            .streams(|streams| streams.local_bidi(0).local_uni(128))
            .try_build())
        .expect("fixture configuration must satisfy its declared bounds")
    };
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(config(), config()).expect("the bounded connection pair must initialize");
    let mut peers = Vec::new();
    for index in 0..128_u8 {
        let id = (client.send_streams().open_uni()).expect("the configured stream must open");
        let peer = (id.bind(&server)).expect("the paired receive identity must resolve");
        assert!(client.send_streams().send(id, &[index; 64]).is_ok());
        if index % 3 == 0 {
            assert!(client.send_streams().reset(id, Code::from_u8(7)).is_ok());
        }
        peers.push(peer);
    }

    let mut received = vec![Vec::new(); 128];
    let mut resets = Vec::new();
    let mut now = Instant::now();
    for _ in 0..256 {
        now = client.view().recovery().send_at(now);
        assert!(server.receive_from(&mut work, &mut client, now).is_ok());
        for (index, peer) in peers.iter().enumerate() {
            if index % 3 == 0 {
                continue;
            }
            let bytes = (server.recv().recv_owned(*peer))
                .expect("the configured receive capacity must admit the stream");
            if let Some(bytes) = bytes {
                received[index].extend(bytes);
            }
        }
        while let Some(event) = server.poll().poll_event() {
            if let Event::Reset {
                stream_id: id,
                error_code: code,
            } = event
            {
                assert!(code == Code::from_u8(7));
                assert!(!resets.contains(&id));
                resets.push(id);
            }
        }
        now = server.view().recovery().send_at(now);
        assert!(client.receive_from(&mut work, &mut server, now).is_ok());
        if resets.len() == 43
            && received
                .iter()
                .enumerate()
                .all(|(index, bytes)| index % 3 == 0 || bytes.len() == 64)
        {
            break;
        }
        now += Duration::from_millis(1);
    }
    assert_eq!(resets.len(), 43);
    for (index, bytes) in received.iter().enumerate() {
        if index % 3 != 0 {
            assert_eq!(bytes.as_slice(), &[index as u8; 64]);
        }
    }
}
