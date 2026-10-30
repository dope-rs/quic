pub mod common;

use common::peer;
use common::suite::peers::{mutual::Pair, tls::Forged};
use dope_quic::conn;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::wire::Handshake;
use dope_quic::wire::packet::cid;
use dope_tls::config::raw::Identity;
use rustls::{AlertDescription, CertificateError, Error, PeerIncompatible};
use std::time::Instant;

#[test]
fn pinned_client_accepted() {
    let result = Pair::try_new(
        Some(Identity::from_seed(&[0x52; 32]).expect("raw client identity")),
        true,
    )
    .expect("mutual-auth fixture")
    .try_run()
    .expect("mutual-auth handshake output");
    assert!(
        result.cli && result.srv && result.cli_err.is_empty() && result.srv_err.is_empty(),
        "mutual-auth handshake completes when the verifier authorizes the client"
    );
}

#[test]
fn unauthorized_denied() {
    let result = Pair::try_new(
        Some(Identity::from_seed(&[0x52; 32]).expect("raw client identity")),
        false,
    )
    .expect("mutual-auth fixture")
    .try_run()
    .expect("mutual-auth handshake output");
    assert!(
        !result.srv,
        "server must not establish when the verifier rejects the client key"
    );
    assert!(!result.srv_err.is_empty());
    assert!(result.srv_err.into_iter().all(|error| matches!(
        error,
        conn::Error::Handshake(Handshake {
            error: Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            alert: Some(AlertDescription::AccessDenied),
        })
    )));
    assert!(
        result
            .cli_err
            .into_iter()
            .all(|error| matches!(error, conn::Error::PeerClosed))
    );
}

#[test]
fn anonymous_client_denied() {
    let result = Pair::try_new(None, true)
        .expect("anonymous-client fixture")
        .try_run()
        .expect("anonymous-client handshake output");
    assert!(
        !result.srv,
        "Required mode must reject a client that presents no certificate"
    );
    assert!(!result.srv_err.is_empty());
    assert!(result.srv_err.into_iter().all(|error| {
        matches!(
            error,
            conn::Error::Handshake(Handshake {
                error: Error::PeerIncompatible(PeerIncompatible::IncorrectCertificateTypeExtension),
                alert: Some(AlertDescription::HandshakeFailure),
            })
        )
    }));
    assert!(
        result
            .cli_err
            .into_iter()
            .all(|error| matches!(error, conn::Error::PeerClosed))
    );
}

#[test]
fn forged_signature() {
    let now = Instant::now();
    for corrupt in [false, true] {
        let id = cid::Id::try_from([0x73; 8]).expect("fixture connection identity");
        let mut pair =
            peer::Pair::try_config(Options::default(), Options::default(), id, |server, _| {
                if corrupt {
                    Forged::install(server);
                }
            })
            .expect("pinned server fixture");
        if !corrupt {
            pair.exchange(now, 6).expect("valid pinned handshake");
            pair.try_ready()
                .expect("valid signature establishes both peers");
            continue;
        }
        let (emitted_packets, send_result) =
            pair.client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("client Initial");
        for mut packet in emitted_packets {
            pair.server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut pair.work)
                        .recv_packet(&mut packet, now, |_: &Error| {})
                })
                .expect("server receives Initial");
        }
        let mut observed = 0;
        let mut rejected = 0;
        let (emitted_packets, send_result) =
            pair.server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("server CertificateVerify flight");
        for mut packet in emitted_packets {
            let mut replay = packet.clone();
            let result = pair.client.with_scope(|mut scope| {
                scope
                    .input(&mut pair.work)
                    .recv_packet(&mut packet, now, |cause: &Error| {
                        assert_eq!(
                            cause,
                            &Error::InvalidCertificate(CertificateError::BadSignature)
                        );
                        observed += 1;
                    })
            });
            if let Err(error) = result {
                assert!(
                    matches!(
                        error,
                        conn::Error::Handshake(Handshake {
                            error: Error::InvalidCertificate(CertificateError::BadSignature),
                            alert: Some(AlertDescription::DecryptError),
                        })
                    ),
                    "{error:?}"
                );
                rejected += 1;
                pair.client
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut pair.work)
                            .recv_packet(&mut replay, now, |_: &Error| {
                                observed += 1;
                            })
                    })
                    .expect("terminal connection discards the repeated flight");
            }
        }
        assert_eq!(rejected, 1);
        assert_eq!(observed, 1);
        assert!(pair.client.view().lifecycle().is_closing());
        assert!(!pair.server.view().lifecycle().is_ready());
    }
}

/// The packet was not decrypted, admitted, or buffered while the key was
/// pending.  Once Finished promotes that same key, a network retransmission
/// of the exact packet is accepted normally.
#[test]
fn one_rtt_waits_for_finish() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_datagram().expect("mutual-auth datagram fixture");
    let now = Instant::now();

    let (emitted_packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("fresh client journals must admit its Initial");
    for mut packet in emitted_packets {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, now, |_: &Error| {})
            })
            .expect("server must receive the emitted client Initial");
    }
    let (emitted_packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("fresh server journals must admit its handshake flight");
    for mut packet in emitted_packets {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, now, |_: &Error| {})
            })
            .expect("client must receive the emitted server handshake flight");
    }
    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_opening());

    client
        .with_scope(|mut scope| {
            scope
                .datagrams()
                .try_send(b"before client finished".to_vec())
        })
        .expect("established test client must accept the pre-Finished DATAGRAM");
    let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("warmed client journals must admit Finished and the pre-Finished datagram");
    let (mut hs, mut one_rtt): (Vec<_>, Vec<_>) = packets
        .into_iter()
        .partition(|packet| packet[0] & 0x80 != 0);
    assert!(!hs.is_empty(), "client Finished is pending");
    assert!(!one_rtt.is_empty(), "client emitted pre-Finished 1-RTT");

    for packet in &mut one_rtt {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &Error| {})
            })
            .expect("server must process the pre-Finished 1-RTT packet");
    }
    assert!(server.view().lifecycle().is_opening());
    assert_eq!(
        server.with_scope(|mut scope| scope.datagrams().recv()),
        None
    );

    for packet in &mut hs {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &Error| {})
            })
            .expect("server must receive the client Finished packet");
    }
    assert!(server.view().lifecycle().is_ready());
    assert_eq!(
        server.with_scope(|mut scope| scope.datagrams().recv()),
        None
    );

    for packet in &mut one_rtt {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &Error| {})
            })
            .expect("server must receive the retransmitted 1-RTT packet");
    }
    assert_eq!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .as_deref(),
        Some(b"before client finished".as_slice())
    );

    client
        .with_scope(|mut scope| {
            scope
                .datagrams()
                .try_send(b"after client finished".to_vec())
        })
        .expect("established test client must accept the post-Finished DATAGRAM");
    let (emitted_packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("warmed client journals must admit the post-Finished datagram");
    for mut packet in emitted_packets {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, now, |_: &Error| {})
            })
            .expect("server must receive the post-Finished DATAGRAM packet");
    }
    assert_eq!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .as_deref(),
        Some(b"after client finished".as_slice())
    );
}
