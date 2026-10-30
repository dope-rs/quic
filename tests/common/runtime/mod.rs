pub mod embedded;
pub mod gso;
pub mod loopback;
pub mod pooled;
pub mod reap;

pub mod suffix;

use dope_quic::conn::life::options::builder::Invalid;
use dope_quic::conn::wire::path::probe;
use dope_quic::errors;
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder;
use std::{net::SocketAddr, time::Instant};

#[derive(Debug)]
pub enum Error {
    Identity(dope_tls::Error),
    Tls(dope_tls::Error),
    Receive(errors::Receive),
    Output(errors::Transmit),
    Connect(errors::Connect),
    Access(errors::Access),
    Send(errors::SendFailure<Vec<u8>>),
    Limits(builder::Error),
    Storage(builder::Failure),
    Options(Invalid),
    Parameters(param::Error),
    Probe(probe::Error),
    Deadline(Instant),
    EmptyReply,
    RotationUnavailable,
    Certificates(usize),
    CertificateOverflow,
    Established { client: usize, server: usize },
    Route(SocketAddr),
}
