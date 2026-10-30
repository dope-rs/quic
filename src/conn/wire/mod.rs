use rustls::{AlertDescription, Error};

use crate::conn::Epoch;

pub(in crate::conn) mod crypto;
pub mod ingress;
pub mod packet;
pub mod path;
pub(in crate::conn) mod permits;
pub(in crate::conn) mod scratch;
mod storage;
pub(crate) mod tls;

#[derive(Clone, Debug)]
pub struct Handshake {
    pub error: Error,
    pub alert: Option<AlertDescription>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls {
    Output {
        epoch: Epoch,
        actual: usize,
        available: usize,
    },
    Epoch(Epoch),
    MissingApplicationKeys,
    ActiveApplicationKeys,
}
