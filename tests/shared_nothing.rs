use dope_quic::conn::server;
use dope_quic::early_data::ReplayCache;
use dope_quic::mux::Handler;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::server::config::NoGuard;
use shin::server::config::{ClientAuth, ClientCertVerifier, ClientIdentity};

struct Noop;

impl Handler<0> for Noop {
    type Connection = ();

    fn create_connection(
        &mut self,
        _conn: &mut dope_quic::conn::session::Connection,
        _handle: dope_quic::conn::Handle,
    ) {
    }
}

struct Accept;

impl ClientCertVerifier for Accept {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        true
    }
}

fn signing() -> SigningKey {
    SigningKey::from_seed(&[0x91; 32]).unwrap()
}

#[test]
fn lane_owned_security_policies_are_concrete() {
    let mut early = dope_quic::mux::setup::Server::with_early_data_guard(
        Noop,
        signing(),
        Default::default(),
        ReplayCache::new().unwrap(),
    )
    .unwrap();
    assert!(
        early
            .configuration()
            .replace_ticket_keys(Some(Keys::single([0x41; 32]).unwrap()))
    );

    let mut mutual = dope_quic::mux::setup::Server::mutual(
        Noop,
        signing(),
        Default::default(),
        server::Authentication::new(ClientAuth::Required, Accept),
    )
    .unwrap();
    assert!(mutual.configuration().replace_ticket_keys(None));

    let mut combined = dope_quic::mux::setup::Server::mutual_with_early_data_guard(
        Noop,
        signing(),
        Default::default(),
        server::Authentication::with_early_data_guard(
            ReplayCache::new().unwrap(),
            ClientAuth::Required,
            Accept,
        ),
    )
    .unwrap();
    assert!(
        combined
            .configuration()
            .replace_ticket_keys(Some(Keys::single([0x43; 32]).unwrap()))
    );
}

#[test]
fn clients_have_no_ticket_shard() {
    let mut client = dope_quic::mux::setup::Client::new(Noop).build().unwrap();
    assert!(
        !client
            .configuration()
            .replace_ticket_keys(Some(Keys::single([0x42; 32]).unwrap()))
    );
}

#[test]
fn generic_policy_paths_cover_conn_and_mux() {
    let cid = dope_quic::packet::ConnectionId::try_from(&[0x71; 8][..]).unwrap();
    let ids = server::Ids::initial(cid, cid, cid);
    let _server = dope_quic::conn::setup::Server::<0>::accept_with_policy::<server::Standard>(
        ids,
        signing(),
        Default::default(),
        NoGuard,
    )
    .unwrap();

    let authentication = server::Authentication::with_early_data_guard(
        ReplayCache::new().unwrap(),
        ClientAuth::Required,
        Accept,
    );
    let mut mux =
        dope_quic::mux::setup::Server::<server::Mutual<ReplayCache, Accept>>::with_policy(
            Noop,
            signing(),
            Default::default(),
            authentication,
        )
        .unwrap();
    assert!(
        mux.configuration()
            .replace_ticket_keys(Some(Keys::single([0x44; 32]).unwrap()))
    );
}
