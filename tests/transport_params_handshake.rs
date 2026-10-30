pub mod common;

use common::{
    peer,
    suite::peers::packet::{self, params},
};
use dope_quic::{
    conn::{
        self,
        life::{accept, options::Options, tls::clients},
    },
    proto::param,
    runtime::routing,
    wire::{packet::cid, varint::VarInt},
};
use o3::buffer::storage;
use rustls::{client::ClientSessionStore as _, pki_types::ServerName};
use std::{net::Ipv4Addr, sync::Arc, time::Instant};

#[test]
fn preferred_server_only() {
    let (client, server, _) = params::configs().expect("TLS configuration");
    let id = cid::Id::try_from(packet::CID).expect("connection ID");
    let params = param::Set::default();
    let mut encoded = Vec::new();
    params
        .bind_client(&id)
        .encode(&mut encoded)
        .expect("client parameters");
    params::push(
        &mut encoded,
        VarInt::from_u8(0x0d),
        &params::preferred(8)[..49],
    )
    .expect("preferred address parameter");
    let mut client = packet::Session::try_encoded(client, encoded).expect("TLS client");
    let auth = accept::Authority::<0>::new(
        server,
        Options::try_from(params).expect("connection options"),
    )
    .expect("server authority");
    let mut server = auth
        .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
        .expect("server connection");
    let mut work = conn::Workspace::try_new().expect("connection workspace");
    let now = Instant::now();
    server
        .with_scope(|mut scope| {
            scope.input(&mut work).recv_packet(
                &mut client.initial().expect("client Initial"),
                now,
                |_| {},
            )
        })
        .expect("client hello");
    for packet in server.with_scope(|mut scope| {
        let (packets, result) = scope.output().send(now);
        result.expect("server flight");
        packets
    }) {
        let _ = client.receive(&packet).expect("server handshake");
    }
    let result = server.with_scope(|mut scope| {
        scope.input(&mut work).recv_packet(
            &mut client.finish(None).expect("client Finished"),
            now,
            |_| {},
        )
    });
    assert!(matches!(
        result,
        Err(conn::Error::TransportParameterMismatch)
    ));
}

#[test]
fn preferred_server_id() {
    for empty in [false, true] {
        let (client, server, _) = params::configs().expect("TLS configuration");
        let auth =
            clients::Authority::try_new(client, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
                .expect("client authority");
        let id = cid::Id::try_from(packet::CID).expect("connection ID");
        let local = if empty { cid::Id::default() } else { id };
        let params = param::Set::default();
        let mut encoded = Vec::new();
        params
            .bind_server(&local, &id, None, None)
            .encode(&mut encoded)
            .expect("server parameters");
        params::push(
            &mut encoded,
            VarInt::from_u8(0x0d),
            &params::preferred(8)[..49],
        )
        .expect("preferred address parameter");
        let mut server =
            params::Server::try_new(Arc::new(server), local, encoded).expect("TLS server");
        let mut client = auth
            .connect::<0, Vec<u8>, storage::Shared>(
                id,
                id,
                Options::try_from(params).expect("connection options"),
                routing::Plain,
            )
            .expect("client connection");
        let mut work = conn::Workspace::try_new().expect("connection workspace");
        let result = server.exchange(&mut client, &mut work, Instant::now());
        if empty {
            assert!(matches!(
                result,
                Err(packet::Error::Setup(peer::Setup::Client(
                    peer::Transfer::Input(conn::Error::TransportParameterMismatch)
                )))
            ));
        } else {
            result.expect("server preferred address");
            assert!(client.view().lifecycle().is_ready());
        }
    }
}

#[test]
fn early_datagram_priority() {
    for (saved, datagram, data, wrong_id, mismatch) in [
        (64, Some(63), 1024, false, Some(false)),
        (64, None, 1024, false, Some(false)),
        (64, Some(63), 1023, false, Some(true)),
        (64, Some(63), 1024, true, Some(true)),
        (0, None, 1024, false, None),
    ] {
        let (client, server, cache) = params::configs().expect("TLS configuration");
        let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
        let auth = clients::Authority::try_new(client, name.clone()).expect("client authority");
        let config = Arc::new(server);
        let id = cid::Id::try_from(packet::CID).expect("connection ID");
        let old = param::Set::builder()
            .initial_data(1024)
            .datagram(Some(saved))
            .try_build()
            .expect("remembered parameters");
        let mut encoded = Vec::new();
        old.bind_server(&id, &id, None, None)
            .encode(&mut encoded)
            .expect("remembered server parameters");
        let mut server =
            params::Server::try_new(Arc::clone(&config), id, encoded).expect("issuing TLS server");
        let mut client = auth
            .connect::<0, Vec<u8>, storage::Shared>(
                id,
                id,
                Options::try_from(param::Set::default()).expect("connection options"),
                routing::Plain,
            )
            .expect("first client connection");
        let mut work = conn::Workspace::try_new().expect("connection workspace");
        let now = Instant::now();
        for _ in 0..2 {
            server
                .exchange(&mut client, &mut work, now)
                .expect("ticket-issuing handshake");
        }
        assert!(client.view().lifecycle().is_confirmed());
        drop(client);
        let ticket = cache
            .take_tls13_ticket(&name)
            .expect("native session ticket");
        let early = ticket.max_early_data_size();
        let cached = ticket.quic_params();
        cache.insert_tls13_ticket(name, ticket);
        assert_eq!(early, u32::MAX);
        assert_eq!(
            param::Codec::decode(&cached)
                .expect("cached transport parameters")
                .flow()
                .datagram(),
            old.flow().datagram()
        );

        let new = old
            .to_builder()
            .initial_data(data)
            .datagram(datagram)
            .try_build()
            .expect("resumed parameters");
        let initial = if wrong_id { cid::Id::default() } else { id };
        let mut encoded = Vec::new();
        new.bind_server(&initial, &id, None, None)
            .encode(&mut encoded)
            .expect("resumed server parameters");
        let mut server = params::Server::try_new(config, id, encoded).expect("resuming TLS server");
        let mut client = auth
            .connect::<0, Vec<u8>, storage::Shared>(
                id,
                id,
                Options::try_from(param::Set::default()).expect("connection options"),
                routing::Plain,
            )
            .expect("resumed client connection");
        let result = server.exchange(&mut client, &mut work, now);
        assert!(
            client.view().lifecycle().is_early(),
            "saved {saved}, datagram {datagram:?}, data {data}, wrong_id {wrong_id}: {result:?}"
        );
        assert!(matches!(
            (mismatch, result),
            (None, Ok(()))
                | (
                    Some(true),
                    Err(packet::Error::Setup(peer::Setup::Client(
                        peer::Transfer::Input(conn::Error::TransportParameterMismatch)
                    )))
                )
                | (
                    Some(false),
                    Err(packet::Error::Setup(peer::Setup::Client(
                        peer::Transfer::Input(conn::Error::ProtocolViolation)
                    )))
                )
        ));
    }
}
