use crate::common::peer;
pub mod common;
use common::suite::mux::Ignore;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::manage::config::TlsError;
use std::pin::Pin;

use dope_quic::conn::life::accept;
use dope_quic::errors::Connect;
use dope_quic::proto::early::ReplayCap;

trait MaybeSend<A> {}
impl<T: ?Sized> MaybeSend<()> for T {}
impl<T: ?Sized + Send> MaybeSend<u8> for T {}

trait MaybeSync<A> {}
impl<T: ?Sized> MaybeSync<()> for T {}
impl<T: ?Sized + Sync> MaybeSync<u8> for T {}

fn confined<T: ?Sized + MaybeSend<A> + MaybeSync<B>, A, B>() {}

const _: fn() = || {
    use dope_quic::conn::{self, life};
    use life::tls::{clients, servers};
    confined::<conn::Connection, _, _>();
    confined::<life::Connection<'static>, _, _>();
    confined::<life::Reconnect, _, _>();
    confined::<clients::Authority, _, _>();
    confined::<clients::Pool, _, _>();
    confined::<servers::Pool, _, _>();
    confined::<accept::Authority, _, _>();
    use conn::stream::recv::{credit, hold};
    confined::<hold::Held<'static, Vec<u8>>, _, _>();
    confined::<hold::Detached<Vec<u8>>, _, _>();
    confined::<credit::Credit<'static>, _, _>();
    confined::<credit::Credit<'static, credit::Local>, _, _>();
    confined::<credit::Detached, _, _>();
    confined::<credit::Detached<credit::Local>, _, _>();
    confined::<credit::Merge<'static, 'static>, _, _>();
};

#[test]
fn lane_policies_exist() {
    let (_, peer) = peer::raw(0x92).expect("fixture client identity");
    for (mutual, early) in [(false, true), (true, false), (true, true)] {
        let (identity, _) = peer::raw(0x91).expect("fixture server identity");
        let config = if mutual {
            identity.server_auth(peer)
        } else {
            identity.server()
        }
        .expect("fixture server TLS configuration");
        let mut next = config.clone();
        next.send_tls13_tickets = usize::from(early);
        next.max_early_data_size = if early { u32::MAX } else { 0 };
        let auth = if early {
            accept::Authority::with_early(
                config,
                Default::default(),
                ReplayCap::new(64).expect("64 replay entries must fit the replay capacity"),
            )
        } else {
            accept::Authority::new(config, Default::default())
        }
        .expect("TLS policy and replay capacity must form an authority");
        let mut router = Builder::server(Ignore, auth)
            .build()
            .expect("TLS policy must form a server router");
        Pin::new(&mut router)
            .config()
            .reconfigure(next)
            .expect("server authority owns its future handshake configuration");
    }
}

#[test]
fn clients_reject_config() {
    let mut client = Builder::client(Ignore)
        .build()
        .expect("default test client router plan must be valid");
    let (identity, _) = peer::raw(0x42).expect("fixture server identity");
    let config = identity.server().expect("fixture server TLS configuration");
    assert!(matches!(
        Pin::new(&mut client).config().reconfigure(config),
        Err(TlsError::NoServer)
    ));
}

#[test]
fn rejects_invalid_config() {
    let (identity, _) = peer::raw(0x44).expect("fixture server identity");
    let config = identity.server().expect("fixture server TLS configuration");
    let mut next = config.clone();
    next.max_early_data_size = 1;
    let auth = accept::Authority::new(config, Default::default())
        .expect("fixture TLS configuration must form a server authority");
    let mut router = Builder::server(Ignore, auth)
        .build()
        .expect("fixture server router plan must be valid");
    assert!(matches!(
        Pin::new(&mut router).config().reconfigure(next),
        Err(TlsError::Configuration(Connect::InvalidConfig))
    ));
}
