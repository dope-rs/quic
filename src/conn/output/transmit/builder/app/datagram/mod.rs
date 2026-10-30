use o3::buffer;
pub(in crate::conn::output::transmit) mod direct;
mod pooled;

use crate::conn::output;
use crate::conn::output::transmit::{self, builder::pending};
use crate::proto::datagram;
use crate::security::crypto;
use crate::stream;

pub(in crate::conn::output::transmit) use pooled::Pooled;

pub(in crate::conn::output::transmit) enum Outcome<
    'pool,
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    Admission(
        datagram::Packet<'pool>,
        transmit::Admission<crypto::Dimensions>,
    ),
    Rejected(datagram::Packet<'pool>),
    Sealed(
        datagram::Sealed<'pool>,
        pending::Packet<'connection, DOMAIN, B, D>,
        output::Timer,
    ),
    Crypto(crypto::Error),
}
