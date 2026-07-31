use dope_quic::client_auth::{ClientAuth, ClientCertVerifier, ClientIdentity};
use dope_quic::early_data::EarlyDataReplayCache;
use dope_quic::{Conn, Handler, Mutual, MutualAuthentication, Mux, ServerConnectionIds, Standard};
use shin::server::config::NoGuard;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::TicketKeys;

struct Noop;

impl Handler for Noop {}

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
    let mut early = Mux::server_with_early_data_guard(
        Noop,
        signing(),
        Default::default(),
        EarlyDataReplayCache::new(),
    )
    .unwrap();
    assert!(early.replace_ticket_keys(Some(TicketKeys::single([0x41; 32]))));

    let mut mutual = Mux::server_mutual(
        Noop,
        signing(),
        Default::default(),
        MutualAuthentication::new(ClientAuth::Required, Accept),
    )
    .unwrap();
    assert!(mutual.replace_ticket_keys(None));

    let mut combined = Mux::server_mutual_with_early_data_guard(
        Noop,
        signing(),
        Default::default(),
        MutualAuthentication::with_early_data_guard(
            EarlyDataReplayCache::new(),
            ClientAuth::Required,
            Accept,
        ),
    )
    .unwrap();
    assert!(combined.replace_ticket_keys(Some(TicketKeys::single([0x43; 32]))));
}

#[test]
fn clients_have_no_ticket_shard() {
    let mut client = Mux::client(Noop).unwrap();
    assert!(!client.replace_ticket_keys(Some(TicketKeys::single([0x42; 32]))));
}

#[test]
fn generic_policy_paths_cover_conn_and_mux() {
    let cid = vec![0x71; 8];
    let ids = ServerConnectionIds::initial(cid.clone(), cid.clone(), cid);
    let _server =
        Conn::new_server_with_policy::<Standard>(ids, signing(), Default::default(), NoGuard)
            .unwrap();

    let authentication = MutualAuthentication::with_early_data_guard(
        EarlyDataReplayCache::new(),
        ClientAuth::Required,
        Accept,
    );
    let mut mux = Mux::<_, Mutual<EarlyDataReplayCache, Accept>>::server_with_policy(
        Noop,
        signing(),
        Default::default(),
        authentication,
    )
    .unwrap();
    assert!(mux.replace_ticket_keys(Some(TicketKeys::single([0x44; 32]))));
}
