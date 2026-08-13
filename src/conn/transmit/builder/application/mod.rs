pub(in crate::conn::transmit) mod datagram;
pub(in crate::conn::transmit) mod one_rtt;
pub(in crate::conn::transmit) mod terminal;
pub(in crate::conn::transmit) mod zero_rtt;

use crate::stream;

use crate::conn::transmit::builder;

pub(in crate::conn::transmit) struct Application<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    packet: builder::Builder<'a, DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Application<'a, DOMAIN, B> {
    pub(in crate::conn::transmit) fn new(
        connection: &'a mut crate::conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self {
            packet: builder::Builder::new(connection),
        }
    }
}
