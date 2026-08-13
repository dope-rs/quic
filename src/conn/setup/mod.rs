pub(crate) mod build;

use shin::crypto;

use crate::conn;
use crate::errors;
use crate::packet;

pub struct Client<const DOMAIN: u8 = 0> {
    initial_dcid: packet::ConnectionId,
    local_cid: packet::ConnectionId,
    server_pubkey: [u8; 32],
    options: conn::config::Options,
}

impl<const DOMAIN: u8> Client<DOMAIN> {
    pub fn connect_pooled<'pool>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        pool: &'pool conn::tls::ClientPool,
        options: conn::config::Options,
    ) -> Result<conn::tls::Connection<'pool, DOMAIN>, errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::new(&initial_dcid)
            .ok_or(errors::ConnectFailure::InvalidConfig)?;
        let local_cid =
            packet::ConnectionId::new(&local_cid).ok_or(errors::ConnectFailure::InvalidConfig)?;
        Self::connect_pooled_buffer(initial_dcid, local_cid, pool, options)
    }

    pub(crate) fn connect_pooled_buffer<'pool, B: crate::stream::ReceiveBuffer>(
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        pool: &'pool conn::tls::ClientPool,
        options: conn::config::Options,
    ) -> Result<conn::tls::Connection<'pool, DOMAIN, B>, errors::ConnectFailure> {
        options.validate_pooled_client()?;
        let built = build::Builder::<
            shin::server::config::NoGuard,
            shin::server::config::NoClientAuth,
            DOMAIN,
        >::client_pooled(initial_dcid, local_cid, pool, options)
        .finish::<B>()?;
        let build::Built::ClientPooled { connection, tls } = built else {
            return Err(errors::ConnectFailure::InvalidConfig);
        };
        Ok(conn::tls::Connection::new(connection, tls))
    }

    pub fn connect(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        server_pubkey: [u8; 32],
        options: conn::config::Options,
    ) -> Result<conn::session::Connection<DOMAIN>, errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::new(&initial_dcid)
            .ok_or(errors::ConnectFailure::InvalidConfig)?;
        let local_cid =
            packet::ConnectionId::new(&local_cid).ok_or(errors::ConnectFailure::InvalidConfig)?;
        Self::connect_buffer(initial_dcid, local_cid, server_pubkey, options)
    }

    pub(crate) fn connect_buffer<B: crate::stream::ReceiveBuffer>(
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        server_pubkey: [u8; 32],
        options: conn::config::Options,
    ) -> Result<conn::session::Connection<DOMAIN, B>, errors::ConnectFailure> {
        let setup = Self {
            initial_dcid,
            local_cid,
            server_pubkey,
            options,
        };
        setup.finish_buffer()
    }

    fn finish_buffer<B: crate::stream::ReceiveBuffer>(
        self,
    ) -> Result<conn::session::Connection<DOMAIN, B>, errors::ConnectFailure> {
        self.options.validate()?;
        let built = build::Builder::<
            shin::server::config::NoGuard,
            shin::server::config::NoClientAuth,
            DOMAIN,
        >::client(
            self.initial_dcid,
            self.local_cid,
            self.server_pubkey,
            self.options,
        )
        .finish::<B>()?;
        let build::Built::Client(mut connection) = built else {
            return Err(errors::ConnectFailure::InvalidConfig);
        };
        let outcome = connection
            .handshake
            .start_client()
            .map_err(|_| errors::ConnectFailure::Tls)?;
        outcome.apply(&mut connection);
        Ok(connection)
    }
}

pub struct Server<const DOMAIN: u8 = 0> {
    ids: conn::server::Ids,
    signing_key: crypto::sig::SigningKey,
    options: conn::config::Options,
}

impl<const DOMAIN: u8> Server<DOMAIN> {
    pub fn accept_pooled<'pool, G, V>(
        ids: conn::server::Ids,
        options: conn::config::Options,
        pool: &'pool shin::server::workspace::QuicPool<conn::handshake::Clock, V, DOMAIN, G>,
    ) -> Result<conn::tls::ServerConnection<'pool, G, V, DOMAIN>, errors::ConnectFailure>
    where
        G: shin::server::config::EarlyDataGuard,
        V: shin::server::config::ClientCertVerifier,
    {
        let options = conn::config::Validated::new_pooled_server(options)?;
        let built = build::Builder::server_pooled(ids, options, pool).finish()?;
        let build::Built::ServerPooled { connection, tls } = built else {
            return Err(errors::ConnectFailure::InvalidConfig);
        };
        Ok(conn::tls::ServerConnection::new(connection, tls))
    }

    fn initial(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
    ) -> Result<Self, errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let local_cid = packet::ConnectionId::try_from(local_cid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let peer_cid = packet::ConnectionId::try_from(peer_cid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        Ok(Self {
            ids: conn::server::Ids::initial(initial_dcid, local_cid, peer_cid),
            signing_key,
            options,
        })
    }

    pub fn accept(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
    ) -> Result<
        conn::server::Connection<
            shin::server::config::NoGuard,
            shin::server::config::NoClientAuth,
            DOMAIN,
        >,
        errors::ConnectFailure,
    > {
        let setup = Self::initial(initial_dcid, local_cid, peer_cid, signing_key, options)?;
        setup.finish::<conn::server::Standard>(shin::server::config::NoGuard)
    }

    pub fn accept_retry(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        original_dcid: Vec<u8>,
        retry_scid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
    ) -> Result<
        conn::server::Connection<
            shin::server::config::NoGuard,
            shin::server::config::NoClientAuth,
            DOMAIN,
        >,
        errors::ConnectFailure,
    > {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let local_cid = packet::ConnectionId::try_from(local_cid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let peer_cid = packet::ConnectionId::try_from(peer_cid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let original_dcid = packet::ConnectionId::try_from(original_dcid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let retry_scid = packet::ConnectionId::try_from(retry_scid)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let setup = Self {
            ids: conn::server::Ids::retry(
                initial_dcid,
                local_cid,
                peer_cid,
                original_dcid,
                retry_scid,
            ),
            signing_key,
            options,
        };
        setup.finish::<conn::server::Standard>(shin::server::config::NoGuard)
    }

    pub fn accept_with_guard<G>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
        guard: G,
    ) -> Result<
        conn::server::Connection<G, shin::server::config::NoClientAuth, DOMAIN>,
        errors::ConnectFailure,
    >
    where
        G: conn::server::ReplayGuard + 'static,
    {
        let setup = Self::initial(initial_dcid, local_cid, peer_cid, signing_key, options)?;
        setup.finish::<conn::server::Standard<G>>(guard)
    }

    pub fn accept_mutual<V>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
        authentication: conn::server::Authentication<V>,
    ) -> Result<
        conn::server::Connection<
            shin::server::config::NoGuard,
            shin::server::config::ClientAuthVerifier<V>,
            DOMAIN,
        >,
        errors::ConnectFailure,
    >
    where
        V: shin::server::config::ClientCertVerifier + 'static,
    {
        let setup = Self::initial(initial_dcid, local_cid, peer_cid, signing_key, options)?;
        setup.finish::<conn::server::Mutual<shin::server::config::NoGuard, V>>(authentication)
    }

    pub fn accept_mutual_with_guard<G, V>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
    ) -> Result<
        conn::server::Connection<G, shin::server::config::ClientAuthVerifier<V>, DOMAIN>,
        errors::ConnectFailure,
    >
    where
        G: conn::server::ReplayGuard + 'static,
        V: shin::server::config::ClientCertVerifier + 'static,
    {
        let setup = Self::initial(initial_dcid, local_cid, peer_cid, signing_key, options)?;
        setup.finish::<conn::server::Mutual<G, V>>(authentication)
    }

    pub fn accept_with_policy<P>(
        ids: conn::server::Ids,
        signing_key: crypto::sig::SigningKey,
        options: conn::config::Options,
        policy: P::Setup,
    ) -> Result<conn::server::Connection<P::Guard, P::Verifier, DOMAIN>, errors::ConnectFailure>
    where
        P: conn::server::Policy,
    {
        let setup = Self {
            ids,
            signing_key,
            options,
        };
        setup.finish::<P>(policy)
    }

    fn finish<P>(
        self,
        policy: P::Setup,
    ) -> Result<conn::server::Connection<P::Guard, P::Verifier, DOMAIN>, errors::ConnectFailure>
    where
        P: conn::server::Policy,
    {
        let mut options = conn::config::Validated::new(self.options)?;
        let shard_config = options.take_server_config(self.signing_key)?;
        let shard =
            P::build::<DOMAIN>(shard_config, policy).map_err(|_| errors::ConnectFailure::Tls)?;
        let (connection, tls) = build::Builder::server(self.ids, options, &shard)
            .finish()?
            .into_server()
            .ok_or(errors::ConnectFailure::InvalidConfig)?;
        Ok(conn::server::Connection::new(connection, tls, shard))
    }
}
