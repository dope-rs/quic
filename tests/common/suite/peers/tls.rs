use crate::common::peer;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::life::tls::{clients, servers};
use dope_quic::proto::epoch;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZero;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use dope_quic::conn::{id, life};
use dope_quic::errors;
use dope_quic::proto::param;
use dope_quic::runtime::mux::{app, auth, handler, output, router};
use dope_quic::wire::packet::cid;
use handler::hook::{
    data::release,
    life::{create, ready},
    set,
    wire::cert,
};
use life::accept;
use o3::buffer::storage;
use peer::Setup;

use crate::common::suite::openssl;
use dope_test::harness::support::file::{self, Directory};
use dope_tls::config::{self, Ext as _, ProviderExt as _};
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer};
use rustls::server::{ClientHello, ResolvesServerCert, VerifierBuilderError, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    ClientConfig, ServerConfig, SignatureAlgorithm, SignatureScheme, crypto::CryptoProvider,
};

pub fn client(pin: [u8; 32]) -> Result<clients::Authority, dope_tls::Error> {
    let config = config::raw::Identity::client(pin)?;
    Ok(clients::Authority::try_new(
        config,
        ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()),
    )?)
}

/// Retains the resolved identity and changes only its CertificateVerify signature.
#[derive(Debug)]
pub struct Forged<T>(T);

impl Forged<Arc<dyn ResolvesServerCert>> {
    pub fn install(config: &mut ServerConfig) {
        config.cert_resolver = Arc::new(Self(Arc::clone(&config.cert_resolver)));
    }
}

impl ResolvesServerCert for Forged<Arc<dyn ResolvesServerCert>> {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut key = (*self.0.resolve(hello)?).clone();
        key.key = Arc::new(Forged(key.key));
        Some(Arc::new(key))
    }

    fn only_raw_public_keys(&self) -> bool {
        self.0.only_raw_public_keys()
    }
}

impl SigningKey for Forged<Arc<dyn SigningKey>> {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(Forged(self.0.choose_scheme(offered)?)))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl Signer for Forged<Box<dyn Signer>> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signed = self.0.sign(message)?;
        if let Some(byte) = signed.first_mut() {
            *byte ^= 1;
        }
        Ok(signed)
    }

    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

#[derive(Default)]
pub struct Capture {
    pub established: usize,
    pub certificates: usize,
    pub last_created: Option<id::Handle>,
}

#[derive(Debug)]
pub enum Transfer {
    Output(errors::Transmit),
    Input(errors::Receive),
    Certificates(usize),
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set<set::On>;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut handler, _, handle) = event.into_parts();
        handler.last_created = Some(handle);
    }
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut handler, _, _, _) = event.into();
        handler.established += 1;
    }
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut handler, _, _, _) = event.into_parts();
        handler.certificates += 1;
    }
}

impl Capture {
    pub fn take(
        mux: &mut router::Router<Capture, 0, Vec<u8>, auth::Pooled<'_>>,
        now: Instant,
    ) -> Result<Vec<output::Flight>, errors::Transmit> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.output().drive()?;
            Ok(turn.output().drain().collect())
        })
    }

    pub fn discard(
        mux: &mut router::Router<Capture, 0, Vec<u8>, auth::Pooled<'_>>,
        now: Instant,
    ) -> Result<(), errors::Transmit> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.output().drive()?;
            for flight in turn.output().drain() {
                drop(flight);
            }
            Ok(())
        })
    }

    pub fn deliver(
        mux: &mut router::Router<Capture, 0, Vec<u8>, auth::Pooled<'_>>,
        from: SocketAddr,
        packets: &mut [output::Flight],
        now: Instant,
    ) -> Result<(), Transfer> {
        Pin::new(&mut *mux).observe(now, |mut turn| -> Result<(), Transfer> {
            for packet in packets {
                for segment in packet.segments_mut() {
                    turn.protocol()
                        .recv(from, segment, epoch::WALL_CLOCK)
                        .map_err(Transfer::Input)?;
                }
            }
            Ok(())
        })?;
        match mux.handler().certificates {
            0 => Ok(()),
            count => Err(Transfer::Certificates(count)),
        }
    }

    pub fn relay(
        source: &mut router::Router<Capture, 0, Vec<u8>, auth::Pooled<'_>>,
        target: &mut router::Router<Capture, 0, Vec<u8>, auth::Pooled<'_>>,
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), Transfer> {
        let mut packets = Self::take(source, now).map_err(Transfer::Output)?;
        Self::deliver(target, from, &mut packets, now)
    }

    pub fn prepare(
        seed: u8,
        tickets: bool,
        options: Options,
    ) -> Result<(servers::Pool, clients::Pool, cid::Id), Setup> {
        let (key, pubkey) = peer::raw(seed).map_err(Setup::Identity)?;
        let mut config = key.server().map_err(Setup::Tls)?;
        let mut client = config::raw::Identity::client(pubkey).map_err(Setup::Tls)?;
        if tickets {
            config.send_tls13_tickets = 2;
            client.resumption = Resumption::in_memory_sessions(16);
        }
        let auth = accept::Authority::new(config, options).map_err(Setup::Authority)?;
        let servers = servers::Pool::new(auth, NonZero::<usize>::MIN);
        let client =
            clients::Authority::try_new(client, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
                .map_err(|cause| Setup::Authority(cause.into()))?;
        let clients = clients::Pool::new(client, NonZero::<usize>::MIN);
        let cid = cid::Id::try_from([0x42; 8]).map_err(Setup::Id)?;
        Ok((servers, clients, cid))
    }

    pub fn options() -> Result<Options, Setup> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .try_build()
            .map_err(Setup::Params)?;
        Options::try_from(params).map_err(Setup::Options)
    }
}

#[derive(Clone, Copy)]
pub enum Kind {
    Raw,
    X509,
}

#[derive(Debug)]
pub enum Init {
    Directory(file::Error),
    OpenSsl(openssl::Init),
    Tls(dope_tls::Error),
    Verifier(VerifierBuilderError),
}

impl Kind {
    pub fn configs(
        self,
        base: &Path,
        cleanup: impl FnOnce(Result<(), file::Remove>),
    ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), Init> {
        match self {
            Self::Raw => {
                let (server, remote) = peer::raw(0x60).map_err(Init::Tls)?;
                let (client, local) = peer::raw(0x61).map_err(Init::Tls)?;
                Ok((
                    client.mutual(remote).map_err(Init::Tls)?,
                    server.server_auth(local).map_err(Init::Tls)?,
                ))
            }
            Self::X509 => {
                let root = Directory::try_with(base, "quic-certificate", cleanup)
                    .map_err(Init::Directory)?;
                let identity = openssl::Identity::new(root.path()).map_err(Init::OpenSsl)?;
                drop(root);
                let chain: Vec<_> = identity
                    .chain
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect();
                let key = PrivatePkcs8KeyDer::from(identity.key);
                let mut roots = rustls::RootCertStore::empty();
                for cert in &chain {
                    roots
                        .add(cert.clone())
                        .map_err(dope_tls::Error::Tls)
                        .map_err(Init::Tls)?;
                }
                let roots = Arc::new(roots);
                let client = ClientConfig::try_tls13()
                    .map_err(Init::Tls)?
                    .with_root_certificates(Arc::clone(&roots))
                    .with_client_auth_cert(chain.clone(), key.clone_key().into())
                    .map_err(dope_tls::Error::Tls)
                    .map_err(Init::Tls)?;
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(roots, CryptoProvider::tls13())
                        .build()
                        .map_err(Init::Verifier)?;
                let mut server = ServerConfig::try_tls13()
                    .map_err(Init::Tls)?
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(chain, key.into())
                    .map_err(dope_tls::Error::Tls)
                    .map_err(Init::Tls)?;
                server.send_tls13_tickets = 0;
                Ok((client, server))
            }
        }
    }

    pub const fn oid(&self) -> &[u8] {
        match self {
            Self::Raw => &[0x06, 0x03, 0x2b, 0x65, 0x70],
            Self::X509 => &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        }
    }

    pub fn error(self) -> rustls::CertificateError {
        match self {
            Self::Raw => rustls::CertificateError::ApplicationVerificationFailure,
            Self::X509 => rustls::CertificateError::BadSignature,
        }
    }

    pub fn alert(self) -> rustls::AlertDescription {
        match self {
            Self::Raw => rustls::AlertDescription::AccessDenied,
            Self::X509 => rustls::AlertDescription::DecryptError,
        }
    }

    fn check(self, cause: &rustls::Error) -> Result<(), &rustls::Error> {
        if cause == &rustls::Error::InvalidCertificate(self.error()) {
            Ok(())
        } else {
            Err(cause)
        }
    }
}

pub struct Rejected<const RELEASE: bool, F> {
    kind: Kind,
    pub certificates: usize,
    pub released: usize,
    check: F,
}

impl<const RELEASE: bool, F> Rejected<RELEASE, F> {
    pub const fn new(kind: Kind, check: F) -> Self {
        Self {
            kind,
            certificates: 0,
            released: 0,
            check,
        }
    }
}

impl<F: FnMut(Result<(), &rustls::Error>) + Unpin> handler::Handler<0, Vec<u8>, storage::Shared>
    for Rejected<false, F>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set;
}

impl<F: FnMut(Result<(), &rustls::Error>) + Unpin> handler::Handler<0, Vec<u8>, storage::Shared>
    for Rejected<true, F>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<set::Off, set::Off, set::Off, set::Off, set::On>;
}

impl<const RELEASE: bool, F: FnMut(Result<(), &rustls::Error>) + Unpin> cert::Sink<0, id::Static>
    for Rejected<RELEASE, F>
where
    Self: handler::Handler<0, Vec<u8>, storage::Shared>,
{
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut capture, _, _, cause) = event.into_parts();
        let result = capture.kind.check(cause);
        (capture.check)(result);
        capture.certificates += 1;
    }
}

impl<F: FnMut(Result<(), &rustls::Error>) + Unpin>
    release::Sink<0, Vec<u8>, storage::Shared, id::Static> for Rejected<true, F>
{
    fn release(event: release::Event<'_, Self, 0, id::Static>) -> app::Readiness {
        let (mut capture, _, _) = event.into_parts();
        capture.released += 1;
        app::Readiness::Preserve
    }
}
