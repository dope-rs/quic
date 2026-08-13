pub(in crate::conn::transmit) mod datagram;
pub(in crate::conn::transmit) mod one_rtt;
pub(in crate::conn::transmit) mod terminal;
pub(in crate::conn::transmit) mod zero_rtt;

use crate::conn::Connection;
use crate::stream::ReceiveBuffer;

use super::Builder;

pub(in crate::conn::transmit) struct Application<'a, const DOMAIN: u8, B: ReceiveBuffer> {
    packet: Builder<'a, DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: ReceiveBuffer> Application<'a, DOMAIN, B> {
    pub(in crate::conn::transmit) fn new(connection: &'a mut Connection<DOMAIN, B>) -> Self {
        Self {
            packet: Builder::new(connection),
        }
    }
}
