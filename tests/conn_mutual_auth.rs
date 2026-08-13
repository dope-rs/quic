use std::time::Instant;

use dope_quic::client_auth::{ClientAuth, ClientCertVerifier, ClientIdentity, Identity};
use dope_quic::conn::server;
use dope_quic::{conn, transport_params};
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [0x42; 8];

fn ed25519(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

fn base_cfg() -> conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        ..transport_params::Params::default()
    }
    .into()
}

struct PinVerifier {
    accept: bool,
}

impl ClientCertVerifier for PinVerifier {
    fn verify(&self, _identity: &ClientIdentity<'_>) -> bool {
        self.accept
    }
}

fn run(identity: Option<Identity>, mode: ClientAuth, accept: bool) -> (bool, bool) {
    let server_key = ed25519(0x51);
    let server_pubkey = *server_key.pubkey().unwrap();

    let mut client_cfg = base_cfg();
    client_cfg.identity = identity;

    let mut server = dope_quic::conn::setup::Server::<0>::accept_mutual(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        server_key,
        base_cfg(),
        server::Authentication::new(mode, PinVerifier { accept }),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        client_cfg,
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();

    for _ in 0..6 {
        let now = Instant::now();
        for mut packet in client.transmit().send(now) {
            let _ = server.recv_packet(&mut workspace, &mut packet, now);
        }
        for mut packet in server.transmit().send(now) {
            let _ = client.recv_packet(&mut workspace, &mut packet, now);
        }
    }
    (
        client.status().is_established(),
        server.status().is_established(),
    )
}

#[test]
fn mutual_auth_required_accepts_pinned_client() {
    let (client_est, server_est) = run(
        Some(Identity::RawPublicKey {
            signing_key: ed25519(0x52),
        }),
        ClientAuth::Required,
        true,
    );
    assert!(
        client_est && server_est,
        "mutual-auth handshake completes when the verifier authorizes the client"
    );
}

#[test]
fn mutual_auth_rejects_unauthorized_client() {
    let (_client_est, server_est) = run(
        Some(Identity::RawPublicKey {
            signing_key: ed25519(0x52),
        }),
        ClientAuth::Required,
        false,
    );
    assert!(
        !server_est,
        "server must not establish when the verifier rejects the client key"
    );
}

#[test]
fn mutual_auth_required_rejects_anonymous() {
    let (_client_est, server_est) = run(None, ClientAuth::Required, true);
    assert!(
        !server_est,
        "Required mode must reject a client that presents no certificate"
    );
}
