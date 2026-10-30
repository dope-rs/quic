pub mod common;

use common::peer::{self, Config, Pair, Receiver as _, Setup, Transfer};
use dope_quic::conn::life::{accept, options::Options, tls::clients};
use dope_quic::proto::early::ReplayCap;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_quic::{conn, conn::Epoch};
use dope_tls::config;
use o3::buffer::storage;
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore as _, Resumption};
use rustls::pki_types::ServerName;
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

#[test]
fn ticket_survives_pto() {
    let cache = Arc::new(ClientSessionMemoryCache::new(16));
    let id = cid::Id::try_from([0x71; 8]).expect("connection ID");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_config(
        Options::default(),
        Options::default(),
        id,
        |server, client| {
            server.send_tls13_tickets = 1;
            client.resumption = Resumption::store(cache.clone());
        },
    )
    .expect("ticket fixture must open");
    let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
    let sent_at = Instant::now();
    let mut dropped = false;
    for _ in 0..6 {
        server
            .receive_from(&mut work, &mut client, sent_at)
            .expect("client flight");
        let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(sent_at));
        send_result.expect("server handshake output");
        for mut packet in packets {
            if packet.first().is_some_and(|byte| byte & 0x80 == 0) {
                dropped = true;
                continue;
            }
            client
                .receive(&mut work, &mut packet, sent_at)
                .expect("server handshake flight");
        }
    }
    assert!(dropped, "server emits Application CRYPTO");
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    assert_ne!(server.view().recovery().unacked(Epoch::Application), 0);
    assert!(cache.take_tls13_ticket(&name).is_none());

    let deadline = server
        .view()
        .recovery()
        .next_timer()
        .expect("ticket loss arms PTO");
    let probe_at = deadline + Duration::from_millis(1);
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    let (mut probes, send_result) = server.with_scope(|mut scope| scope.output().send(probe_at));
    send_result.expect("ticket retransmission");
    assert!(!probes.is_empty());
    for packet in &mut probes {
        client
            .receive(&mut work, packet, probe_at)
            .expect("ticket probe");
    }
    server
        .receive_from(&mut work, &mut client, probe_at)
        .expect("ticket acknowledgement");
    assert!(
        cache.take_tls13_ticket(&name).is_some(),
        "retransmitted CRYPTO reaches the native cache"
    );
}

#[test]
fn native_session_policy() {
    let (signing, pin) = peer::raw(0x77).expect("server identity");
    let (identity, peer) = peer::raw(0x78).expect("client identity");
    let mut server = signing
        .server_auth(peer)
        .expect("mutual server configuration");
    server.send_tls13_tickets = 2;
    let auth = accept::Authority::with_early(
        server,
        Config::default()
            .try_build()
            .expect("server transport options"),
        ReplayCap::new(16).expect("retained server sessions"),
    )
    .expect("server authority");
    let mut config = identity.mutual(pin).expect("mutual client configuration");
    config.enable_early_data = true;
    config.resumption = Resumption::in_memory_sessions(16);
    let name = ServerName::try_from(String::from("localhost")).expect("server name");
    let source = {
        let original =
            clients::Authority::try_new(config.clone(), name.clone()).expect("client authority");
        original.try_clone().expect("authority reference")
    };
    let (identity, other) = peer::raw(0x79).expect("different identity");
    let mut wrong = config::raw::Identity::client(other).expect("different server verifier");
    wrong.enable_early_data = true;
    wrong.resumption = config.resumption.clone();
    wrong.client_auth_cert_resolver = config.client_auth_cert_resolver.clone();
    let mut changed = config.clone();
    changed.client_auth_cert_resolver = identity
        .mutual(pin)
        .expect("different client credentials")
        .client_auth_cert_resolver;
    let id = cid::Id::try_from([0x73; 8]).expect("connection ID");
    let now = Instant::now();
    for (config, name, early, valid) in [
        (wrong, name.clone(), false, false),
        (
            config.clone(),
            ServerName::try_from("changed.example").expect("different cache name"),
            false,
            true,
        ),
        (changed, name.clone(), false, false),
        (config, name, true, true),
    ] {
        let mut first = Pair {
            server: auth
                .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
                .expect("issuing server"),
            client: source
                .connect::<0, Vec<u8>, storage::Shared>(
                    id,
                    id,
                    Config::default().try_build().expect("client options"),
                    routing::Plain,
                )
                .expect("issuing client"),
            work: conn::Workspace::try_new().expect("receive workspace"),
        };
        first
            .exchange(now, 6)
            .expect("warm actual native session cache");
        first.try_ready().expect("issuing handshake");
        drop(first);
        let client = clients::Authority::try_new(config, name).expect("client authority");
        let mut pair = Pair {
            server: auth
                .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
                .expect("selected server"),
            client: client
                .connect::<0, Vec<u8>, storage::Shared>(
                    id,
                    id,
                    Config::default().try_build().expect("client options"),
                    routing::Plain,
                )
                .expect("selected client policy"),
            work: conn::Workspace::try_new().expect("receive workspace"),
        };
        drop(client);
        let stream = pair
            .client
            .with_scope(|mut scope| scope.streams().send().open_bidi().map(|stream| stream.id()));
        assert_eq!(
            stream.is_ok(),
            early,
            "only the compatible selected ticket supplies early credit"
        );
        if early {
            let stream = stream.expect("native cached credit");
            pair.client.with_scope(|mut scope| {
                let stream = scope
                    .streams()
                    .view()
                    .resolve_bidi(stream)
                    .expect("opened stream");
                scope
                    .streams()
                    .send()
                    .send(stream.send(), b"native")
                    .expect("early payload");
            });
            pair.server
                .receive_from(&mut pair.work, &mut pair.client, now)
                .expect("selected early flight");
            assert!(!pair.server.view().lifecycle().is_ready());
            let mut got = Vec::new();
            pair.server.with_scope(|mut scope| {
                let stream = scope
                    .streams()
                    .view()
                    .resolve_recv(stream)
                    .expect("incoming stream");
                assert_eq!(scope.streams().receive().recv(stream, &mut got), Ok(6));
            });
            assert_eq!(got, b"native");
        }
        if valid {
            pair.exchange(now, 6)
                .expect("current native policy handshake");
            pair.try_ready().expect("current policy authenticates");
            assert_eq!(pair.client.view().lifecycle().is_early(), early);
        } else {
            let failure = pair
                .exchange(now, 6)
                .expect_err("current verifier and client credentials must be used");
            assert!(matches!(
                failure,
                Setup::Client(Transfer::Input(conn::Error::Handshake(cause)))
                    | Setup::Server(Transfer::Input(conn::Error::Handshake(cause)))
                    if matches!(cause.error, rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure
                    ))
            ));
        }
    }
}

#[test]
fn changed_alpn_rejects() {
    let (signing, pin) = peer::raw(0x7a).expect("server identity");
    let mut config = signing.server().expect("server configuration");
    config.alpn_protocols = vec![b"h3".to_vec(), b"other".to_vec()];
    config.send_tls13_tickets = 1;
    let server = accept::Authority::with_early(
        config,
        Config::default()
            .try_build()
            .expect("server transport options"),
        ReplayCap::new(1).expect("one retained session"),
    )
    .expect("server authority");
    let mut config = config::raw::Identity::client(pin).expect("client configuration");
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;
    config.resumption = Resumption::in_memory_sessions(16);
    let name = ServerName::try_from("localhost").expect("server name");
    let source =
        clients::Authority::try_new(config.clone(), name.clone()).expect("client authority");
    let id = cid::Id::try_from([0x74; 8]).expect("connection ID");
    let now = Instant::now();
    let mut first = Pair {
        server: server
            .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
            .expect("issuing server"),
        client: source
            .connect::<0, Vec<u8>, storage::Shared>(
                id,
                id,
                Config::default().try_build().expect("client options"),
                routing::Plain,
            )
            .expect("issuing client"),
        work: conn::Workspace::try_new().expect("receive workspace"),
    };
    first.exchange(now, 6).expect("warm h3 session");
    first.try_ready().expect("issuing handshake");
    drop(first);
    config.alpn_protocols = vec![b"other".to_vec()];
    let client = clients::Authority::try_new(config, name).expect("client authority");
    let mut pair = Pair {
        server: server
            .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
            .expect("selected server"),
        client: client
            .connect::<0, Vec<u8>, storage::Shared>(
                id,
                id,
                Config::default().try_build().expect("client options"),
                routing::Plain,
            )
            .expect("changed application policy"),
        work: conn::Workspace::try_new().expect("receive workspace"),
    };
    pair.client
        .with_scope(|mut scope| scope.streams().send().open_bidi().map(|_| ()))
        .expect("native ticket offers cached early credit");
    pair.exchange(now, 6)
        .expect("current application protocol handshake");
    pair.try_ready()
        .expect("both peers negotiate the current application protocol");
    assert!(!pair.client.view().lifecycle().is_early());
    assert!(!pair.server.view().lifecycle().is_early());
}
