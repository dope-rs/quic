use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use dope_quic::client_auth::{ClientAuth, ClientCertSource, ClientCertVerifier, ClientIdentity};
use dope_quic::{Conn, ConnClientAuth, ConnConfig, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42; 8];

fn drain(from: &mut Conn, into: &mut Conn) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        let _ = into.recv_packet(&pkt, now);
    }
}

fn ed25519() -> SigningKey {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    SigningKey::from_seed(&seed).unwrap()
}

fn base_cfg() -> ConnConfig {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        ..transport_params::Params::default()
    }
    .into()
}

struct PinVerifier {
    accept: bool,
    seen: RefCell<Option<(u8, Vec<u8>)>>,
}

impl ClientCertVerifier for PinVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        *self.seen.borrow_mut() = Some((identity.cert_type, identity.spki_der.to_vec()));
        self.accept
    }
}

fn run(
    client_cert: Option<ClientCertSource>,
    mode: ClientAuth,
    accept: bool,
) -> (bool, bool, Rc<PinVerifier>) {
    let server_key = ed25519();
    let server_pubkey = *server_key.pubkey().unwrap();
    let verifier = Rc::new(PinVerifier {
        accept,
        seen: RefCell::new(None),
    });

    let mut server_cfg = base_cfg();
    server_cfg.client_auth = Some(ConnClientAuth {
        mode,
        verifier: verifier.clone(),
    });
    let mut client_cfg = base_cfg();
    client_cfg.client_cert = client_cert;

    let mut server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        server_key,
        server_cfg,
    );
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, client_cfg);

    for _ in 0..6 {
        drain(&mut client, &mut server);
        drain(&mut server, &mut client);
    }
    (client.is_established(), server.is_established(), verifier)
}

#[test]
fn mutual_auth_required_accepts_pinned_client() {
    let (client_est, server_est, verifier) = run(
        Some(ClientCertSource::RawPublicKey {
            signing_key: ed25519(),
        }),
        ClientAuth::Required,
        true,
    );
    assert!(
        client_est && server_est,
        "mutual-auth handshake completes when the verifier authorizes the client"
    );
    let seen = verifier.seen.borrow();
    let (cert_type, spki) = seen
        .as_ref()
        .expect("verifier was handed a client identity");
    assert_eq!(*cert_type, 2, "RawPublicKey cert type (RFC 7250)");
    assert!(!spki.is_empty(), "a non-empty SPKI to pin on");
}

#[test]
fn mutual_auth_rejects_unauthorized_client() {
    let (_client_est, server_est, verifier) = run(
        Some(ClientCertSource::RawPublicKey {
            signing_key: ed25519(),
        }),
        ClientAuth::Required,
        false,
    );
    assert!(
        !server_est,
        "server must not establish when the verifier rejects the client key"
    );
    assert!(
        verifier.seen.borrow().is_some(),
        "possession was proven (verifier consulted) before the authorization rejection"
    );
}

#[test]
fn mutual_auth_required_rejects_anonymous() {
    let (_client_est, server_est, _verifier) = run(None, ClientAuth::Required, true);
    assert!(
        !server_est,
        "Required mode must reject a client that presents no certificate"
    );
}
