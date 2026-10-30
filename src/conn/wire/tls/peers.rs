use std::net;

use o3::{
    buffer::write::{Reserved, Sink as _},
    mem::rc,
};

use crate::{
    conn::life::{self, tls::clients},
    wire::packet::cid,
};

const MAX_ADDRESS_TOKEN_BYTES: usize = 4096;

pub(in crate::conn) struct State<A = Option<clients::Authority>> {
    early_data_accepted: bool,
    address_token_authority: A,
    address_token: Option<(life::Token, net::SocketAddr)>,
}

impl<A> State<A> {
    pub(super) fn new(auth: A) -> Self {
        Self {
            early_data_accepted: false,
            address_token_authority: auth,
            address_token: None,
        }
    }

    pub(super) fn accept_early(&mut self) {
        self.early_data_accepted = true;
    }

    pub(in crate::conn) fn is_early(&self) -> bool {
        self.early_data_accepted
    }
}

impl State<()> {
    pub(super) fn bind_auth(self, auth: clients::Authority) -> State {
        State {
            early_data_accepted: self.early_data_accepted,
            address_token_authority: Some(auth),
            address_token: self.address_token,
        }
    }
}

impl State {
    pub(in crate::conn) fn store_token(&mut self, token: &[u8], peer: Option<net::SocketAddr>) {
        let (Some(_), Some(peer)) = (&self.address_token_authority, peer) else {
            return;
        };
        if token.is_empty() || token.len() > MAX_ADDRESS_TOKEN_BYTES {
            return;
        }
        let mut wire = self
            .address_token
            .take()
            .map(|(token, _)| token.into_wire())
            .unwrap_or_default();
        wire.clear();
        let Ok(reserved) = Reserved::try_exact(&mut wire, token.len()) else {
            return;
        };
        let mut staged = reserved.into_staged();
        if staged.write_slice(token).is_err() {
            return;
        }
        staged.commit();
        self.address_token = Some((life::Token::new(wire), peer));
    }

    pub(in crate::conn) fn try_saved(
        &mut self,
        route: cid::Id,
    ) -> Result<Option<life::Reconnect>, rc::Error> {
        let (Some(auth), Some(_)) = (&self.address_token_authority, &self.address_token) else {
            return Ok(None);
        };
        let auth = auth.try_clone()?;
        Ok(self
            .address_token
            .take()
            .map(|(token, peer)| life::Reconnect::new(token, auth, peer, route)))
    }
}

impl<A> State<Option<A>> {
    /// Moves the final authority edge while its connection is being retired.
    pub(in crate::conn) fn take_final(&mut self) -> Option<(life::Token, A, net::SocketAddr)> {
        let auth = self.address_token_authority.take()?;
        match self.address_token.take() {
            Some((token, peer)) => Some((token, auth, peer)),
            None => {
                self.address_token_authority = Some(auth);
                None
            }
        }
    }
}
