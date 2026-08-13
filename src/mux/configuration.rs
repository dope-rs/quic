use std::io;

use dope::manifold::datagram;
use shin::crypto::ticket::Keys;

use crate::conn;
use crate::stream::ReceiveBuffer;

use super::{Handler, MAX_CONNECTIONS, Router};

pub struct Control<'a, 'tls, H, P, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    mux: &'a mut Router<'tls, H, P, DOMAIN, B>,
}

impl<'a, 'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Control<'a, 'tls, H, P, DOMAIN, B>
{
    pub(super) fn new(mux: &'a mut Router<'tls, H, P, DOMAIN, B>) -> Self {
        Self { mux }
    }

    pub fn enable_gso(&mut self) -> io::Result<()> {
        let Some(limits) = datagram::GSO_LIMITS.filter(|limits| {
            limits.max_segments > 1
                && limits.max_segments <= usize::from(u8::MAX)
                && limits.max_bytes != 0
        }) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "datagram segmentation offload is unavailable",
            ));
        };
        self.mux.outgoing.batch = Some(conn::packet::Gso::new(limits));
        Ok(())
    }

    pub fn disable_gso(&mut self) {
        self.mux.outgoing.batch = None;
    }

    #[must_use]
    pub fn set_max_connections(&mut self, max: usize) -> bool {
        if self.mux.lifecycle.shutting_down
            || self.mux.registry.active_conns != 0
            || max == 0
            || max > MAX_CONNECTIONS
        {
            return false;
        }
        self.mux.registry.resize(max);
        true
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<Keys>) -> bool {
        let Some(server) = self.mux.server.as_mut() else {
            return false;
        };
        server.shard().replace_ticket_keys(keys);
        true
    }
}
