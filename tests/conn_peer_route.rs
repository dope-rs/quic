pub mod common;

use common::peer::{self, Receiver as _};
use common::suite::peers::{
    config::Parameters as _,
    packet::{self, bytes, params},
    tls,
};
use common::suite::{mux::dispatch, tokens};
use dope_quic::conn::{self, life::accept, life::options::Options, life::tls::clients};
use dope_quic::errors;
use dope_quic::proto::{epoch, param};
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::routing::{self, PeerRoute as _};
use dope_quic::wire::{frame, packet::cid, packet::long::initial};
use dope_test::alloc::Tracker;
use o3::buffer::storage;
use rustls::client::ClientSessionStore as _;
use rustls::pki_types::ServerName;
use std::{pin::Pin, sync::Arc, time::Instant};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn retains_peer_route() {
    let (identity, key) = peer::raw(0x39).expect("fixture identity");
    let auth = tls::client(key).expect("fixture client");
    let server = accept::Authority::<0>::new(
        identity.server().expect("fixture server"),
        Options::try_pto().expect("server options"),
    )
    .expect("server authority");
    let shard = routing::Shard::from_index(3);
    let plain = routing::Plain.issue([0x42; 8]);
    let routed = shard.issue([0x43; 8]);
    let other = routing::Shard::from_index(4).issue([0x44; 8]);
    for (route, remote, accepted) in [
        (None, routed, true),
        (Some(shard), routed, true),
        (Some(shard), other, false),
        (Some(shard), plain, false),
    ] {
        let initial = route.map_or(plain, |route| route.issue([0x45; 8]));
        let options = Options::try_pto().expect("client options");
        let mut client = match route {
            Some(route) => {
                auth.connect::<0, Vec<u8>, storage::Shared>(initial, plain, options, route)
            }
            None => {
                auth.connect::<0, Vec<u8>, storage::Shared>(initial, plain, options, routing::Plain)
            }
        }
        .expect("route admission");
        let mut server = server
            .accept::<storage::Shared>(accept::Ids::initial(initial, remote, plain))
            .expect("server admission");
        let mut work = conn::Workspace::try_new().expect("workspace");
        let now = Instant::now();
        server
            .receive_from(&mut work, &mut client, now)
            .expect("client Initial");
        let result = client.receive_from(&mut work, &mut server, now);
        if accepted {
            result.expect("peer CID satisfies the retained route");
            server
                .receive_from(&mut work, &mut client, now)
                .expect("client handshake completion");
            assert!(client.view().lifecycle().is_ready());
            assert!(server.view().lifecycle().is_ready());
        } else {
            assert!(matches!(
                result,
                Err(peer::Transfer::Input(conn::Error::ProtocolViolation))
            ));
        }
    }
}

#[test]
fn accepts_opaque_peer_cids() {
    let now = Instant::now();
    let mut pair = packet::Pair::try_new(1, now, |_| {}).expect("peer handshake");
    for sequence in 1..=2 {
        let id = cid::Id::try_from([sequence; 9]).expect("peer CID");
        let notice = bytes::notice_with_id(sequence, sequence, id.as_ref_id()).expect("CID update");
        pair.receive(&notice, now).expect("opaque peer CID");
    }
    assert!(pair.server.view().lifecycle().is_ready());
}

#[test]
fn reuses_opaque_peer_cid() {
    let (config, policy, cache) = params::configs().expect("resumption configuration");
    let name = ServerName::try_from("localhost").expect("server name");
    let auth = clients::Authority::try_new(config, name.clone()).expect("client authority");
    let policy = Arc::new(policy);
    let initial = cid::Id::try_from(packet::CID).expect("initial CID");
    let remote = cid::Id::try_from([0x63; 9]).expect("opaque server CID");
    let options = Options::try_pto().expect("transport options");
    let mut encoded = Vec::new();
    options
        .params()
        .bind_server(&remote, &initial, None, None)
        .encode(&mut encoded)
        .expect("server transport parameters");
    let mut server = params::Server::try_new(Arc::clone(&policy), remote, encoded.clone())
        .expect("native server");
    let mut client = Builder::client(tokens::Capture::default())
        .build()
        .expect("client mux");
    let mut now = Instant::now();
    let handle = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(tokens::SERVER, &auth, options, packet::CID.to_vec())
        })
        .expect("plain connection");
    for _ in 0..3 {
        now = client
            .conn(handle)
            .expect("connection")
            .view()
            .recovery()
            .send_at(now);
        for mut flight in dispatch::Capture::output(&mut client, now).expect("client output") {
            for packet in flight.segments_mut() {
                server.receive(packet).expect("native server input");
            }
        }
        for mut packet in server.send().expect("native server output") {
            Pin::new(&mut client)
                .observe(now, |mut turn| {
                    turn.protocol()
                        .recv(tokens::SERVER, &mut packet, epoch::WALL_CLOCK)
                })
                .expect("client input");
        }
    }
    assert!(
        client
            .conn(handle)
            .expect("connection")
            .view()
            .lifecycle()
            .is_ready()
    );
    assert!(
        client
            .conn(handle)
            .expect("connection")
            .view()
            .lifecycle()
            .is_confirmed()
    );
    let ticket = cache
        .take_tls13_ticket(&name)
        .expect("cached native ticket");
    let max = ticket.max_early_data_size();
    let cached = ticket.quic_params();
    cache.insert_tls13_ticket(name, ticket);
    assert_eq!(max, u32::MAX);
    let cached = param::Codec::decode(&cached).expect("cached native peer parameters");
    assert!(cached.identity().initial() == Some(&remote));
    let mut token = server
        .packet(bytes::ADDRESS_TOKEN)
        .expect("address token packet");
    let saved = Pin::new(&mut client).observe(now, |mut turn| {
        turn.protocol()
            .recv(tokens::SERVER, &mut token, epoch::WALL_CLOCK)
            .expect("address token input");
        turn.protocol()
            .with_conn(handle, |mut scope| scope.security().try_saved())
            .expect("saved connection")
            .expect("retained authority")
            .expect("saved reconnect owner")
    });
    drop(saved);
    let mut token = server
        .packet(bytes::ADDRESS_TOKEN)
        .expect("second address token packet");
    let mut larger = server
        .packet(&[frame::TYPE_NEW_TOKEN, 2, 0x43, 0x44])
        .expect("larger address token packet");
    let mut retry = server
        .packet(bytes::ADDRESS_TOKEN)
        .expect("retried address token packet");
    let mut reused = server
        .packet(&[frame::TYPE_NEW_TOKEN, 1, 0x45])
        .expect("replacement address token packet");
    let saved = Pin::new(&mut client).observe(now, |mut turn| {
        turn.protocol()
            .recv(tokens::SERVER, &mut token, epoch::WALL_CLOCK)
            .expect("second address token input");
        let (result, activity) = Tracker::measure(|| {
            Tracker::fail_after(0, || {
                turn.protocol()
                    .recv(tokens::SERVER, &mut larger, epoch::WALL_CLOCK)
            })
        });
        result.expect("token allocation failure keeps the connection live");
        assert_eq!(activity, [0, 0, 1, 1]);
        assert!(
            turn.protocol()
                .with_conn(handle, |mut scope| scope.security().try_saved())
                .expect("live connection after failed token growth")
                .expect("retained authority after failed token growth")
                .is_none()
        );
        turn.protocol()
            .recv(tokens::SERVER, &mut retry, epoch::WALL_CLOCK)
            .expect("address token retries after allocation failure");
        let (result, activity) = Tracker::measure(|| {
            Tracker::fail_after(0, || {
                turn.protocol()
                    .recv(tokens::SERVER, &mut reused, epoch::WALL_CLOCK)
            })
        });
        result.expect("same capacity replacement needs no allocation");
        assert_eq!(activity, [0; 4]);
        turn.protocol()
            .with_conn(handle, |mut scope| scope.security().try_saved())
            .expect("live connection after extracting a token")
            .expect("retained authority after extracting a token")
            .expect("second reconnect owner")
    });
    drop(client);
    let other = routing::Shard::from_index(0x64);
    let failure = auth
        .reconnect::<0>(
            other.issue([0x65; 8]),
            initial,
            Options::try_pto().expect("routed reconnect options"),
            saved,
            other,
        )
        .err()
        .expect("saved CID retains its routed shard restriction");
    assert!(matches!(failure.error(), errors::Connect::InvalidConfig));
    let saved = failure.into_parts().1.expect("rejection retains owner");
    let mut resumed = auth
        .reconnect::<0>(
            initial,
            initial,
            Options::try_pto().expect("reconnect options"),
            saved,
            routing::Plain,
        )
        .map_err(|failure| failure.into_parts().0)
        .expect("opaque peer CID remains compatible with Plain");
    assert!(resumed.view().peer().params().is_some());
    let mut server =
        params::Server::try_new(policy, remote, encoded).expect("resuming native server");
    let mut work = conn::Workspace::try_new().expect("workspace");
    let at = resumed.view().recovery().send_at(now);
    let (flight, send_result) = resumed.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("reconnect Initial flight");
    assert!(!flight.is_empty());
    for packet in flight {
        let prefix = initial::Prefix::decode(&packet).expect("reconnect Initial prefix");
        assert_eq!(prefix.token, [0x45]);
        let _ = server.receive(&packet).expect("reconnect Initial input");
    }
    for _ in 0..3 {
        server
            .exchange(&mut resumed, &mut work, now)
            .expect("resumed handshake");
    }
    assert!(resumed.view().lifecycle().is_ready());
    assert!(resumed.view().lifecycle().is_early());
}
